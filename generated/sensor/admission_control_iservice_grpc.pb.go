// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v4.22.0
// source: internalapi/sensor/admission_control_iservice.proto

package sensor

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	AdmissionControlManagementService_Communicate_FullMethodName  = "/sensor.AdmissionControlManagementService/Communicate"
	AdmissionControlManagementService_PolicyAlerts_FullMethodName = "/sensor.AdmissionControlManagementService/PolicyAlerts"
)

// AdmissionControlManagementServiceClient is the client API for AdmissionControlManagementService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type AdmissionControlManagementServiceClient interface {
	Communicate(ctx context.Context, opts ...grpc.CallOption) (AdmissionControlManagementService_CommunicateClient, error)
	PolicyAlerts(ctx context.Context, in *AdmissionControlAlerts, opts ...grpc.CallOption) (*emptypb.Empty, error)
}

type admissionControlManagementServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewAdmissionControlManagementServiceClient(cc grpc.ClientConnInterface) AdmissionControlManagementServiceClient {
	return &admissionControlManagementServiceClient{cc}
}

func (c *admissionControlManagementServiceClient) Communicate(ctx context.Context, opts ...grpc.CallOption) (AdmissionControlManagementService_CommunicateClient, error) {
	stream, err := c.cc.NewStream(ctx, &AdmissionControlManagementService_ServiceDesc.Streams[0], AdmissionControlManagementService_Communicate_FullMethodName, opts...)
	if err != nil {
		return nil, err
	}
	x := &admissionControlManagementServiceCommunicateClient{stream}
	return x, nil
}

type AdmissionControlManagementService_CommunicateClient interface {
	Send(*MsgFromAdmissionControl) error
	Recv() (*MsgToAdmissionControl, error)
	grpc.ClientStream
}

type admissionControlManagementServiceCommunicateClient struct {
	grpc.ClientStream
}

func (x *admissionControlManagementServiceCommunicateClient) Send(m *MsgFromAdmissionControl) error {
	return x.ClientStream.SendMsg(m)
}

func (x *admissionControlManagementServiceCommunicateClient) Recv() (*MsgToAdmissionControl, error) {
	m := new(MsgToAdmissionControl)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *admissionControlManagementServiceClient) PolicyAlerts(ctx context.Context, in *AdmissionControlAlerts, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, AdmissionControlManagementService_PolicyAlerts_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AdmissionControlManagementServiceServer is the server API for AdmissionControlManagementService service.
// All implementations must embed UnimplementedAdmissionControlManagementServiceServer
// for forward compatibility
type AdmissionControlManagementServiceServer interface {
	Communicate(AdmissionControlManagementService_CommunicateServer) error
	PolicyAlerts(context.Context, *AdmissionControlAlerts) (*emptypb.Empty, error)
	mustEmbedUnimplementedAdmissionControlManagementServiceServer()
}

// UnimplementedAdmissionControlManagementServiceServer must be embedded to have forward compatible implementations.
type UnimplementedAdmissionControlManagementServiceServer struct {
}

func (UnimplementedAdmissionControlManagementServiceServer) Communicate(AdmissionControlManagementService_CommunicateServer) error {
	return status.Errorf(codes.Unimplemented, "method Communicate not implemented")
}
func (UnimplementedAdmissionControlManagementServiceServer) PolicyAlerts(context.Context, *AdmissionControlAlerts) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method PolicyAlerts not implemented")
}
func (UnimplementedAdmissionControlManagementServiceServer) mustEmbedUnimplementedAdmissionControlManagementServiceServer() {
}

// UnsafeAdmissionControlManagementServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to AdmissionControlManagementServiceServer will
// result in compilation errors.
type UnsafeAdmissionControlManagementServiceServer interface {
	mustEmbedUnimplementedAdmissionControlManagementServiceServer()
}

func RegisterAdmissionControlManagementServiceServer(s grpc.ServiceRegistrar, srv AdmissionControlManagementServiceServer) {
	s.RegisterService(&AdmissionControlManagementService_ServiceDesc, srv)
}

func _AdmissionControlManagementService_Communicate_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(AdmissionControlManagementServiceServer).Communicate(&admissionControlManagementServiceCommunicateServer{stream})
}

type AdmissionControlManagementService_CommunicateServer interface {
	Send(*MsgToAdmissionControl) error
	Recv() (*MsgFromAdmissionControl, error)
	grpc.ServerStream
}

type admissionControlManagementServiceCommunicateServer struct {
	grpc.ServerStream
}

func (x *admissionControlManagementServiceCommunicateServer) Send(m *MsgToAdmissionControl) error {
	return x.ServerStream.SendMsg(m)
}

func (x *admissionControlManagementServiceCommunicateServer) Recv() (*MsgFromAdmissionControl, error) {
	m := new(MsgFromAdmissionControl)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _AdmissionControlManagementService_PolicyAlerts_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AdmissionControlAlerts)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AdmissionControlManagementServiceServer).PolicyAlerts(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AdmissionControlManagementService_PolicyAlerts_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AdmissionControlManagementServiceServer).PolicyAlerts(ctx, req.(*AdmissionControlAlerts))
	}
	return interceptor(ctx, in, info, handler)
}

// AdmissionControlManagementService_ServiceDesc is the grpc.ServiceDesc for AdmissionControlManagementService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var AdmissionControlManagementService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "sensor.AdmissionControlManagementService",
	HandlerType: (*AdmissionControlManagementServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "PolicyAlerts",
			Handler:    _AdmissionControlManagementService_PolicyAlerts_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Communicate",
			Handler:       _AdmissionControlManagementService_Communicate_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "internalapi/sensor/admission_control_iservice.proto",
}
