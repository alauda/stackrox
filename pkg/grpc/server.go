package grpc

import (
	"context"
	"crypto/tls"
	golog "log"
	"net"
	"net/http"
	"strings"

	"bitbucket.org/stack-rox/apollo/pkg/grpc/authn/mtls"
	"bitbucket.org/stack-rox/apollo/pkg/grpc/authz/deny"
	"bitbucket.org/stack-rox/apollo/pkg/grpc/routes"
	"bitbucket.org/stack-rox/apollo/pkg/logging"
	"bitbucket.org/stack-rox/apollo/pkg/mtls/verifier"
	"github.com/NYTimes/gziphandler"
	"github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/grpc-ecosystem/go-grpc-middleware/auth"
	"github.com/grpc-ecosystem/go-grpc-middleware/tags"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const grpcAddr = ":443"
const endpoint = "localhost" + grpcAddr

var (
	log = logging.New("api")
)

// APIService is the service interface
type APIService interface {
	RegisterServiceServer(server *grpc.Server)
	RegisterServiceHandlerFromEndpoint(context.Context, *runtime.ServeMux, string, []grpc.DialOption) error
}

// API listens for new connections on port 443, and redirects them to the gRPC-Gateway
type API interface {
	// Start runs the API in a goroutine.
	Start()
	// Register adds a new APIService to the list of API services
	Register(service APIService)
}

type apiImpl struct {
	apiServices []APIService
	config      Config
}

// A Config configures the server.
type Config struct {
	TLS                verifier.TLSConfigurer
	CustomRoutes       map[string]routes.CustomRoute
	UnaryInterceptors  []grpc.UnaryServerInterceptor
	StreamInterceptors []grpc.StreamServerInterceptor
}

// NewAPI returns an API object.
func NewAPI(config Config) API {
	return &apiImpl{
		config: config,
	}
}

func (a *apiImpl) Start() {
	go a.run()
}

func (a *apiImpl) Register(service APIService) {
	a.apiServices = append(a.apiServices, service)
}

func (a *apiImpl) unaryInterceptors() []grpc.UnaryServerInterceptor {
	u := []grpc.UnaryServerInterceptor{
		grpc_ctxtags.UnaryServerInterceptor(grpc_ctxtags.WithFieldExtractor(grpc_ctxtags.CodeGenRequestFieldExtractor)),
		mtls.UnaryInterceptor(),
	}
	u = append(u, a.config.UnaryInterceptors...)

	// Default to deny all access. This forces services to properly override the AuthFunc.
	u = append(u, grpc_auth.UnaryServerInterceptor(deny.AuthFunc))

	u = append(u, a.unaryRecovery())
	return u
}

func (a *apiImpl) streamInterceptors() []grpc.StreamServerInterceptor {
	s := []grpc.StreamServerInterceptor{
		grpc_ctxtags.StreamServerInterceptor(grpc_ctxtags.WithFieldExtractor(grpc_ctxtags.CodeGenRequestFieldExtractor)),
		mtls.StreamInterceptor(),
	}
	s = append(s, a.config.StreamInterceptors...)

	// Default to deny all access. This forces services to properly override the AuthFunc.
	s = append(s, grpc_auth.StreamServerInterceptor(deny.AuthFunc))

	s = append(s, a.streamRecovery())
	return s
}

func (a *apiImpl) muxer(tlsConf *tls.Config) http.Handler {
	ctx := context.Background()
	dialCreds := credentials.NewTLS(&tls.Config{
		ServerName:         endpoint,
		RootCAs:            tlsConf.RootCAs,
		InsecureSkipVerify: true,
	})
	dialOpts := []grpc.DialOption{grpc.WithTransportCredentials(dialCreds)}

	mux := http.NewServeMux()
	for prefix, route := range a.config.CustomRoutes {
		mux.Handle(prefix, route.Handler())
	}
	// EmitDefaults marshals zero values into the output, instead of omitting them.
	gwMux := runtime.NewServeMux(runtime.WithMarshalerOption(runtime.MIMEWildcard, &runtime.JSONPb{EmitDefaults: true}))
	for _, service := range a.apiServices {
		if err := service.RegisterServiceHandlerFromEndpoint(ctx, gwMux, endpoint, dialOpts); err != nil {
			panic(err)
		}
	}
	mux.Handle("/v1/", gziphandler.GzipHandler(gwMux))
	return mux
}

func (a *apiImpl) run() {
	tlsConf, err := a.config.TLS.TLSConfig()
	if err != nil {
		panic(err)
	}

	grpcServer := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsConf)),
		grpc.StreamInterceptor(
			grpc_middleware.ChainStreamServer(a.streamInterceptors()...),
		),
		grpc.UnaryInterceptor(
			grpc_middleware.ChainUnaryServer(a.unaryInterceptors()...),
		),
	)

	for _, service := range a.apiServices {
		service.RegisterServiceServer(grpcServer)
	}

	tlsConf.NextProtos = []string{"h2"}
	srv := &http.Server{
		Addr:      endpoint,
		Handler:   wireOrJSONMuxer(grpcServer, a.muxer(tlsConf)),
		ErrorLog:  golog.New(httpErrorLogger{}, "", golog.LstdFlags),
		TLSConfig: tlsConf,
	}
	conn, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		panic(err)
	}
	log.Infof("gRPC server started on %s", grpcAddr)
	err = srv.Serve(tls.NewListener(conn, srv.TLSConfig))
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
	return
}

func wireOrJSONMuxer(grpcServer *grpc.Server, httpHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc") {
			grpcServer.ServeHTTP(w, r)
		} else {
			httpHandler.ServeHTTP(w, r)
		}
	})
}
