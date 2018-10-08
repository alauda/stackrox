package contextutil

import (
	"context"

	"github.com/stackrox/rox/pkg/grpc/util"
	"google.golang.org/grpc"
)

// ContextUpdater is a plain go function that updates a context and returns either a new context or an error.
type ContextUpdater func(context.Context) (context.Context, error)

type contextUpdaterChain []ContextUpdater

func (c contextUpdaterChain) updateContext(ctx context.Context) (lastCtx context.Context, err error) {
	lastCtx = ctx
	for _, updater := range c {
		var newCtx context.Context
		newCtx, err = updater(lastCtx)
		if newCtx != nil {
			lastCtx = newCtx
		}
		if err != nil {
			return
		}
	}
	return
}

// ChainContextUpdaters combines several context updaters into a single one that executes the given updaters from left
// to right, immediately returning if an error is encountered. In the error case, the returned context is not nil, but
// instead the last non-nil context encountered.
func ChainContextUpdaters(updaters ...ContextUpdater) ContextUpdater {
	return contextUpdaterChain(updaters).updateContext
}

// StreamServerInterceptor creates a GRPC stream interceptor that applies the given context updater to the stream's
// context.
func StreamServerInterceptor(updater ContextUpdater) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		newCtx, err := updater(ss.Context())
		if err != nil {
			return err
		}
		wrappedStream := util.StreamWithContext(newCtx, ss)
		return handler(srv, wrappedStream)
	}
}

// UnaryServerInterceptor creates a GRPC unary interceptor that applies the given context updater to the request's
// context.
func UnaryServerInterceptor(updater ContextUpdater) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		newCtx, err := updater(ctx)
		if err != nil {
			return nil, err
		}
		return handler(newCtx, req)
	}
}
