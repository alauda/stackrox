// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: storage/product_usage.proto

package storage

import (
	fmt "fmt"
	_ "github.com/gogo/protobuf/gogoproto"
	types "github.com/gogo/protobuf/types"
	proto "github.com/golang/protobuf/proto"
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

// SecuredUnits represents a record of an aggregated secured clusters usage
// metrics. The metrics are aggregated periodically, and put into the database.
type SecuredUnits struct {
	// id is not used to retrieve data, but serves mostly for compatibility with
	// the current implementation of the query generator.
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty" sql:"pk,type(uuid)"`
	// timestamp stores the moment at which the values of the metrics below are
	// aggregated.
	Timestamp *types.Timestamp `protobuf:"bytes,2,opt,name=timestamp,proto3" json:"timestamp,omitempty" sql:"unique" search:"Timestamp"`
	// num_nodes is the maximum number of secured nodes, observed across all
	// registered clusters during last aggregation period.
	NumNodes int64 `protobuf:"varint,3,opt,name=num_nodes,json=numNodes,proto3" json:"num_nodes,omitempty" search:"Nodes"`
	// num_cpu_units is the maximum number of secured CPU units (which are the
	// units reported by Kubernetes), observed across all registered clusters
	// during last aggregation period.
	NumCpuUnits          int64    `protobuf:"varint,4,opt,name=num_cpu_units,json=numCpuUnits,proto3" json:"num_cpu_units,omitempty" search:"CPU Units"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SecuredUnits) Reset()         { *m = SecuredUnits{} }
func (m *SecuredUnits) String() string { return proto.CompactTextString(m) }
func (*SecuredUnits) ProtoMessage()    {}
func (*SecuredUnits) Descriptor() ([]byte, []int) {
	return fileDescriptor_d14460c8db5fc5db, []int{0}
}
func (m *SecuredUnits) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *SecuredUnits) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_SecuredUnits.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *SecuredUnits) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SecuredUnits.Merge(m, src)
}
func (m *SecuredUnits) XXX_Size() int {
	return m.Size()
}
func (m *SecuredUnits) XXX_DiscardUnknown() {
	xxx_messageInfo_SecuredUnits.DiscardUnknown(m)
}

var xxx_messageInfo_SecuredUnits proto.InternalMessageInfo

func (m *SecuredUnits) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *SecuredUnits) GetTimestamp() *types.Timestamp {
	if m != nil {
		return m.Timestamp
	}
	return nil
}

func (m *SecuredUnits) GetNumNodes() int64 {
	if m != nil {
		return m.NumNodes
	}
	return 0
}

func (m *SecuredUnits) GetNumCpuUnits() int64 {
	if m != nil {
		return m.NumCpuUnits
	}
	return 0
}

func (m *SecuredUnits) MessageClone() proto.Message {
	return m.Clone()
}
func (m *SecuredUnits) Clone() *SecuredUnits {
	if m == nil {
		return nil
	}
	cloned := new(SecuredUnits)
	*cloned = *m

	cloned.Timestamp = m.Timestamp.Clone()
	return cloned
}

func init() {
	proto.RegisterType((*SecuredUnits)(nil), "storage.SecuredUnits")
}

func init() { proto.RegisterFile("storage/product_usage.proto", fileDescriptor_d14460c8db5fc5db) }

var fileDescriptor_d14460c8db5fc5db = []byte{
	// 326 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x44, 0x90, 0xc1, 0x4e, 0xbb, 0x40,
	0x10, 0xc6, 0xff, 0xd0, 0x7f, 0xd4, 0x6e, 0xd5, 0xc3, 0x6a, 0x14, 0x6b, 0x02, 0x64, 0x3d, 0x88,
	0x89, 0x81, 0x44, 0x3d, 0xf5, 0x48, 0xef, 0xc6, 0xa0, 0xbd, 0x98, 0x98, 0x86, 0xc2, 0x8a, 0x9b,
	0x16, 0x76, 0xcb, 0xee, 0x24, 0x7a, 0xf6, 0x25, 0x7c, 0x24, 0x8f, 0x3e, 0x01, 0x31, 0xf5, 0x0d,
	0x78, 0x02, 0xc3, 0x52, 0xea, 0xed, 0xdb, 0x99, 0xef, 0x37, 0x3b, 0xdf, 0xa0, 0x53, 0xa9, 0x78,
	0x19, 0x67, 0x34, 0x10, 0x25, 0x4f, 0x21, 0x51, 0x53, 0x90, 0x71, 0x46, 0x7d, 0x51, 0x72, 0xc5,
	0xf1, 0xf6, 0xba, 0x39, 0x74, 0x32, 0xce, 0xb3, 0x85, 0x36, 0x29, 0x3e, 0x83, 0xe7, 0x40, 0xb1,
	0x9c, 0x4a, 0x15, 0xe7, 0xa2, 0x75, 0x0e, 0x0f, 0x33, 0x9e, 0x71, 0x2d, 0x83, 0x46, 0xb5, 0x55,
	0xf2, 0x6e, 0xa2, 0xdd, 0x7b, 0x9a, 0x40, 0x49, 0xd3, 0x49, 0xc1, 0x94, 0xc4, 0xe7, 0xc8, 0x64,
	0xa9, 0x65, 0xb8, 0x86, 0xd7, 0x0f, 0x8f, 0xeb, 0xca, 0x39, 0x90, 0xcb, 0xc5, 0x88, 0x88, 0xf9,
	0xa5, 0x7a, 0x13, 0xd4, 0x03, 0x60, 0xe9, 0x05, 0x89, 0x4c, 0x96, 0xe2, 0x27, 0xd4, 0xdf, 0x7c,
	0x61, 0x99, 0xae, 0xe1, 0x0d, 0xae, 0x86, 0x7e, 0xbb, 0x84, 0xdf, 0x2d, 0xe1, 0x3f, 0x74, 0x8e,
	0xf0, 0xac, 0xae, 0x1c, 0x47, 0xcf, 0x82, 0x82, 0x2d, 0x81, 0x12, 0x57, 0xd2, 0xb8, 0x4c, 0x5e,
	0x46, 0x64, 0xe3, 0x21, 0xd1, 0xdf, 0x44, 0x1c, 0xa0, 0x7e, 0x01, 0xf9, 0xb4, 0xe0, 0x29, 0x95,
	0x56, 0xcf, 0x35, 0xbc, 0x5e, 0x88, 0xeb, 0xca, 0xd9, 0xef, 0xa8, 0xdb, 0xa6, 0x41, 0xa2, 0x9d,
	0x02, 0x72, 0x2d, 0xf1, 0x08, 0xed, 0x35, 0x40, 0x22, 0x60, 0x0a, 0x4d, 0x12, 0xeb, 0xbf, 0x86,
	0x8e, 0xea, 0xca, 0xc1, 0x1d, 0x34, 0xbe, 0x9b, 0xb8, 0x3a, 0x26, 0x89, 0x06, 0x05, 0xe4, 0x63,
	0x01, 0xfa, 0x15, 0xde, 0x7c, 0xae, 0x6c, 0xe3, 0x6b, 0x65, 0x1b, 0xdf, 0x2b, 0xdb, 0xf8, 0xf8,
	0xb1, 0xff, 0xa1, 0x13, 0xc6, 0x7d, 0xa9, 0xe2, 0x64, 0x5e, 0xf2, 0xd7, 0x36, 0x8e, 0xbf, 0xbe,
	0xf4, 0x63, 0x77, 0xf2, 0xd9, 0x96, 0xae, 0x5f, 0xff, 0x06, 0x00, 0x00, 0xff, 0xff, 0x84, 0x5f,
	0x1f, 0x46, 0xa1, 0x01, 0x00, 0x00,
}

func (m *SecuredUnits) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *SecuredUnits) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *SecuredUnits) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if m.NumCpuUnits != 0 {
		i = encodeVarintProductUsage(dAtA, i, uint64(m.NumCpuUnits))
		i--
		dAtA[i] = 0x20
	}
	if m.NumNodes != 0 {
		i = encodeVarintProductUsage(dAtA, i, uint64(m.NumNodes))
		i--
		dAtA[i] = 0x18
	}
	if m.Timestamp != nil {
		{
			size, err := m.Timestamp.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintProductUsage(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x12
	}
	if len(m.Id) > 0 {
		i -= len(m.Id)
		copy(dAtA[i:], m.Id)
		i = encodeVarintProductUsage(dAtA, i, uint64(len(m.Id)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintProductUsage(dAtA []byte, offset int, v uint64) int {
	offset -= sovProductUsage(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *SecuredUnits) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Id)
	if l > 0 {
		n += 1 + l + sovProductUsage(uint64(l))
	}
	if m.Timestamp != nil {
		l = m.Timestamp.Size()
		n += 1 + l + sovProductUsage(uint64(l))
	}
	if m.NumNodes != 0 {
		n += 1 + sovProductUsage(uint64(m.NumNodes))
	}
	if m.NumCpuUnits != 0 {
		n += 1 + sovProductUsage(uint64(m.NumCpuUnits))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func sovProductUsage(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozProductUsage(x uint64) (n int) {
	return sovProductUsage(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *SecuredUnits) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowProductUsage
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
			return fmt.Errorf("proto: SecuredUnits: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: SecuredUnits: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Id", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowProductUsage
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
				return ErrInvalidLengthProductUsage
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthProductUsage
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Id = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Timestamp", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowProductUsage
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
				return ErrInvalidLengthProductUsage
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthProductUsage
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Timestamp == nil {
				m.Timestamp = &types.Timestamp{}
			}
			if err := m.Timestamp.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field NumNodes", wireType)
			}
			m.NumNodes = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowProductUsage
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.NumNodes |= int64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 4:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field NumCpuUnits", wireType)
			}
			m.NumCpuUnits = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowProductUsage
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.NumCpuUnits |= int64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		default:
			iNdEx = preIndex
			skippy, err := skipProductUsage(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthProductUsage
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
func skipProductUsage(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowProductUsage
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
					return 0, ErrIntOverflowProductUsage
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
					return 0, ErrIntOverflowProductUsage
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
				return 0, ErrInvalidLengthProductUsage
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupProductUsage
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthProductUsage
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthProductUsage        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowProductUsage          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupProductUsage = fmt.Errorf("proto: unexpected end of group")
)