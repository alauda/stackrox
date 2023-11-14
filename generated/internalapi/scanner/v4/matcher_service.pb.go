// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: internalapi/scanner/v4/matcher_service.proto

package v4

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	io "io"
	math "math"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type GetVulnerabilitiesRequest struct {
	HashId               string    `protobuf:"bytes,1,opt,name=hash_id,json=hashId,proto3" json:"hash_id,omitempty"`
	Contents             *Contents `protobuf:"bytes,2,opt,name=contents,proto3" json:"contents,omitempty"`
	XXX_NoUnkeyedLiteral struct{}  `json:"-"`
	XXX_unrecognized     []byte    `json:"-"`
	XXX_sizecache        int32     `json:"-"`
}

func (m *GetVulnerabilitiesRequest) Reset()         { *m = GetVulnerabilitiesRequest{} }
func (m *GetVulnerabilitiesRequest) String() string { return proto.CompactTextString(m) }
func (*GetVulnerabilitiesRequest) ProtoMessage()    {}
func (*GetVulnerabilitiesRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_750c78caaf4a6a6e, []int{0}
}
func (m *GetVulnerabilitiesRequest) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *GetVulnerabilitiesRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_GetVulnerabilitiesRequest.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *GetVulnerabilitiesRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetVulnerabilitiesRequest.Merge(m, src)
}
func (m *GetVulnerabilitiesRequest) XXX_Size() int {
	return m.Size()
}
func (m *GetVulnerabilitiesRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_GetVulnerabilitiesRequest.DiscardUnknown(m)
}

var xxx_messageInfo_GetVulnerabilitiesRequest proto.InternalMessageInfo

func (m *GetVulnerabilitiesRequest) GetHashId() string {
	if m != nil {
		return m.HashId
	}
	return ""
}

func (m *GetVulnerabilitiesRequest) GetContents() *Contents {
	if m != nil {
		return m.Contents
	}
	return nil
}

func (m *GetVulnerabilitiesRequest) MessageClone() proto.Message {
	return m.Clone()
}
func (m *GetVulnerabilitiesRequest) Clone() *GetVulnerabilitiesRequest {
	if m == nil {
		return nil
	}
	cloned := new(GetVulnerabilitiesRequest)
	*cloned = *m

	cloned.Contents = m.Contents.Clone()
	return cloned
}

type Metadata struct {
	LastVulnerabilityUpdate *timestamppb.Timestamp `protobuf:"bytes,1,opt,name=LastVulnerabilityUpdate,proto3" json:"LastVulnerabilityUpdate,omitempty"`
	XXX_NoUnkeyedLiteral    struct{}               `json:"-"`
	XXX_unrecognized        []byte                 `json:"-"`
	XXX_sizecache           int32                  `json:"-"`
}

func (m *Metadata) Reset()         { *m = Metadata{} }
func (m *Metadata) String() string { return proto.CompactTextString(m) }
func (*Metadata) ProtoMessage()    {}
func (*Metadata) Descriptor() ([]byte, []int) {
	return fileDescriptor_750c78caaf4a6a6e, []int{1}
}
func (m *Metadata) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Metadata) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Metadata.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *Metadata) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Metadata.Merge(m, src)
}
func (m *Metadata) XXX_Size() int {
	return m.Size()
}
func (m *Metadata) XXX_DiscardUnknown() {
	xxx_messageInfo_Metadata.DiscardUnknown(m)
}

var xxx_messageInfo_Metadata proto.InternalMessageInfo

func (m *Metadata) GetLastVulnerabilityUpdate() *timestamppb.Timestamp {
	if m != nil {
		return m.LastVulnerabilityUpdate
	}
	return nil
}

func (m *Metadata) MessageClone() proto.Message {
	return m.Clone()
}
func (m *Metadata) Clone() *Metadata {
	if m == nil {
		return nil
	}
	cloned := new(Metadata)
	*cloned = *m

	cloned.LastVulnerabilityUpdate = m.LastVulnerabilityUpdate.Clone()
	return cloned
}

func init() {
	proto.RegisterType((*GetVulnerabilitiesRequest)(nil), "scanner.v4.GetVulnerabilitiesRequest")
	proto.RegisterType((*Metadata)(nil), "scanner.v4.Metadata")
}

func init() {
	proto.RegisterFile("internalapi/scanner/v4/matcher_service.proto", fileDescriptor_750c78caaf4a6a6e)
}

var fileDescriptor_750c78caaf4a6a6e = []byte{
	// 343 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x74, 0x91, 0xc1, 0x4e, 0xea, 0x40,
	0x14, 0x86, 0x6f, 0x59, 0x00, 0x77, 0xd8, 0x4d, 0xc8, 0x85, 0x5b, 0x93, 0x42, 0x30, 0x26, 0x2c,
	0xcc, 0x54, 0x91, 0x9d, 0x3b, 0x8d, 0x21, 0x26, 0xb2, 0x69, 0xd0, 0x85, 0x31, 0xc1, 0xa1, 0x3d,
	0xc0, 0x24, 0xed, 0x4c, 0x9d, 0x39, 0x34, 0xe1, 0x4d, 0x7c, 0x00, 0x1f, 0xc6, 0xa5, 0x8f, 0x60,
	0xf0, 0x45, 0x0c, 0x6d, 0x41, 0x90, 0x74, 0x39, 0x39, 0xdf, 0x3f, 0xff, 0xf9, 0xff, 0x43, 0x4e,
	0x85, 0x44, 0xd0, 0x92, 0x87, 0x3c, 0x16, 0xae, 0xf1, 0xb9, 0x94, 0xa0, 0xdd, 0xa4, 0xef, 0x46,
	0x1c, 0xfd, 0x39, 0xe8, 0xb1, 0x01, 0x9d, 0x08, 0x1f, 0x58, 0xac, 0x15, 0x2a, 0x4a, 0x72, 0x82,
	0x25, 0x7d, 0xbb, 0x35, 0x53, 0x6a, 0x16, 0x82, 0x9b, 0x4e, 0x26, 0x8b, 0xa9, 0x8b, 0x22, 0x02,
	0x83, 0x3c, 0x8a, 0x33, 0xd8, 0x3e, 0xfa, 0x0d, 0x40, 0x14, 0xe3, 0x32, 0x1f, 0x9e, 0x17, 0xf8,
	0x26, 0x8b, 0x50, 0x82, 0xe6, 0x13, 0x11, 0x0a, 0x5c, 0x8e, 0x35, 0xc4, 0x4a, 0x63, 0x2e, 0x39,
	0x2e, 0x90, 0xf8, 0x2a, 0x8a, 0x94, 0xcc, 0xa0, 0xce, 0x94, 0xfc, 0x1f, 0x00, 0x3e, 0xec, 0xfc,
	0x22, 0xc0, 0x78, 0xf0, 0xb2, 0x00, 0x83, 0xb4, 0x41, 0x2a, 0x73, 0x6e, 0xe6, 0x63, 0x11, 0x34,
	0xad, 0xb6, 0xd5, 0xfd, 0xeb, 0x95, 0xd7, 0xcf, 0xdb, 0x80, 0x9e, 0x91, 0xaa, 0xaf, 0x24, 0x82,
	0x44, 0xd3, 0x2c, 0xb5, 0xad, 0x6e, 0xad, 0x57, 0x67, 0x3f, 0x51, 0xd9, 0x75, 0x3e, 0xf3, 0xb6,
	0x54, 0xe7, 0x99, 0x54, 0x87, 0x80, 0x3c, 0xe0, 0xc8, 0xe9, 0x88, 0x34, 0xee, 0xb8, 0xd9, 0x33,
	0x5d, 0xde, 0xc7, 0x01, 0x47, 0x48, 0x6d, 0x6a, 0x3d, 0x9b, 0x65, 0x55, 0xb0, 0x4d, 0x15, 0x6c,
	0xb4, 0xe9, 0xca, 0x2b, 0x92, 0xf6, 0xde, 0x2c, 0x52, 0x19, 0x66, 0x57, 0xa0, 0x4f, 0x84, 0x1e,
	0xa6, 0xa2, 0x27, 0xbb, 0x3b, 0x16, 0xa6, 0xb6, 0x5b, 0xbb, 0xd8, 0x9e, 0x93, 0x97, 0xd6, 0x4b,
	0x2f, 0x49, 0x6d, 0x00, 0xb8, 0x8d, 0xf3, 0xef, 0x60, 0xdb, 0x9b, 0xf5, 0xe1, 0xec, 0xbd, 0x4a,
	0x36, 0xf4, 0x55, 0xfd, 0x7d, 0xe5, 0x58, 0x1f, 0x2b, 0xc7, 0xfa, 0x5c, 0x39, 0xd6, 0xeb, 0x97,
	0xf3, 0xe7, 0xb1, 0x94, 0xf4, 0x27, 0xe5, 0x54, 0x7b, 0xf1, 0x1d, 0x00, 0x00, 0xff, 0xff, 0x1b,
	0x7f, 0x35, 0x2c, 0x5f, 0x02, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// MatcherClient is the client API for Matcher service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConnInterface.NewStream.
type MatcherClient interface {
	// GetVulnerabilities returns a VulnerabilityReport for a previously indexed manifest.
	GetVulnerabilities(ctx context.Context, in *GetVulnerabilitiesRequest, opts ...grpc.CallOption) (*VulnerabilityReport, error)
	// GetMetadata returns information on vulnerability metadata, ek.g., last update timestamp.
	GetMetadata(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*Metadata, error)
}

type matcherClient struct {
	cc grpc.ClientConnInterface
}

func NewMatcherClient(cc grpc.ClientConnInterface) MatcherClient {
	return &matcherClient{cc}
}

func (c *matcherClient) GetVulnerabilities(ctx context.Context, in *GetVulnerabilitiesRequest, opts ...grpc.CallOption) (*VulnerabilityReport, error) {
	out := new(VulnerabilityReport)
	err := c.cc.Invoke(ctx, "/scanner.v4.Matcher/GetVulnerabilities", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *matcherClient) GetMetadata(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*Metadata, error) {
	out := new(Metadata)
	err := c.cc.Invoke(ctx, "/scanner.v4.Matcher/GetMetadata", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// MatcherServer is the server API for Matcher service.
type MatcherServer interface {
	// GetVulnerabilities returns a VulnerabilityReport for a previously indexed manifest.
	GetVulnerabilities(context.Context, *GetVulnerabilitiesRequest) (*VulnerabilityReport, error)
	// GetMetadata returns information on vulnerability metadata, ek.g., last update timestamp.
	GetMetadata(context.Context, *emptypb.Empty) (*Metadata, error)
}

// UnimplementedMatcherServer can be embedded to have forward compatible implementations.
type UnimplementedMatcherServer struct {
}

func (*UnimplementedMatcherServer) GetVulnerabilities(ctx context.Context, req *GetVulnerabilitiesRequest) (*VulnerabilityReport, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetVulnerabilities not implemented")
}
func (*UnimplementedMatcherServer) GetMetadata(ctx context.Context, req *emptypb.Empty) (*Metadata, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetMetadata not implemented")
}

func RegisterMatcherServer(s *grpc.Server, srv MatcherServer) {
	s.RegisterService(&_Matcher_serviceDesc, srv)
}

func _Matcher_GetVulnerabilities_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetVulnerabilitiesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MatcherServer).GetVulnerabilities(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/scanner.v4.Matcher/GetVulnerabilities",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MatcherServer).GetVulnerabilities(ctx, req.(*GetVulnerabilitiesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Matcher_GetMetadata_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(emptypb.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MatcherServer).GetMetadata(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/scanner.v4.Matcher/GetMetadata",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MatcherServer).GetMetadata(ctx, req.(*emptypb.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

var _Matcher_serviceDesc = grpc.ServiceDesc{
	ServiceName: "scanner.v4.Matcher",
	HandlerType: (*MatcherServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetVulnerabilities",
			Handler:    _Matcher_GetVulnerabilities_Handler,
		},
		{
			MethodName: "GetMetadata",
			Handler:    _Matcher_GetMetadata_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "internalapi/scanner/v4/matcher_service.proto",
}

func (m *GetVulnerabilitiesRequest) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *GetVulnerabilitiesRequest) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *GetVulnerabilitiesRequest) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if m.Contents != nil {
		{
			size, err := m.Contents.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintMatcherService(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x12
	}
	if len(m.HashId) > 0 {
		i -= len(m.HashId)
		copy(dAtA[i:], m.HashId)
		i = encodeVarintMatcherService(dAtA, i, uint64(len(m.HashId)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *Metadata) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Metadata) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *Metadata) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if m.LastVulnerabilityUpdate != nil {
		{
			size, err := m.LastVulnerabilityUpdate.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintMatcherService(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintMatcherService(dAtA []byte, offset int, v uint64) int {
	offset -= sovMatcherService(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *GetVulnerabilitiesRequest) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.HashId)
	if l > 0 {
		n += 1 + l + sovMatcherService(uint64(l))
	}
	if m.Contents != nil {
		l = m.Contents.Size()
		n += 1 + l + sovMatcherService(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *Metadata) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.LastVulnerabilityUpdate != nil {
		l = m.LastVulnerabilityUpdate.Size()
		n += 1 + l + sovMatcherService(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func sovMatcherService(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozMatcherService(x uint64) (n int) {
	return sovMatcherService(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *GetVulnerabilitiesRequest) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowMatcherService
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: GetVulnerabilitiesRequest: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: GetVulnerabilitiesRequest: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field HashId", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMatcherService
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthMatcherService
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthMatcherService
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.HashId = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Contents", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMatcherService
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthMatcherService
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthMatcherService
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Contents == nil {
				m.Contents = &Contents{}
			}
			if err := m.Contents.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipMatcherService(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthMatcherService
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *Metadata) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowMatcherService
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Metadata: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Metadata: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field LastVulnerabilityUpdate", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMatcherService
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthMatcherService
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthMatcherService
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.LastVulnerabilityUpdate == nil {
				m.LastVulnerabilityUpdate = &timestamppb.Timestamp{}
			}
			if err := m.LastVulnerabilityUpdate.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipMatcherService(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthMatcherService
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipMatcherService(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowMatcherService
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowMatcherService
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowMatcherService
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthMatcherService
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupMatcherService
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthMatcherService
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthMatcherService        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowMatcherService          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupMatcherService = fmt.Errorf("proto: unexpected end of group")
)
