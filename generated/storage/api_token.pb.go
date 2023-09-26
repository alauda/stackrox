// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: storage/api_token.proto

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

type TokenMetadata struct {
	Id                   string           `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty" sql:"pk"`
	Name                 string           `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty" search:"API Token Name,store" sql:"index=category:unique;name:api_tokens_unique_name"`
	Roles                []string         `protobuf:"bytes,7,rep,name=roles,proto3" json:"roles,omitempty"`
	IssuedAt             *types.Timestamp `protobuf:"bytes,4,opt,name=issued_at,json=issuedAt,proto3" json:"issued_at,omitempty"`
	Expiration           *types.Timestamp `protobuf:"bytes,5,opt,name=expiration,proto3" json:"expiration,omitempty" search:"Expiration,store"`
	Revoked              bool             `protobuf:"varint,6,opt,name=revoked,proto3" json:"revoked,omitempty" search:"Revoked,store"`
	Role                 string           `protobuf:"bytes,3,opt,name=role,proto3" json:"role,omitempty"` // Deprecated: Do not use.
	XXX_NoUnkeyedLiteral struct{}         `json:"-"`
	XXX_unrecognized     []byte           `json:"-"`
	XXX_sizecache        int32            `json:"-"`
}

func (m *TokenMetadata) Reset()         { *m = TokenMetadata{} }
func (m *TokenMetadata) String() string { return proto.CompactTextString(m) }
func (*TokenMetadata) ProtoMessage()    {}
func (*TokenMetadata) Descriptor() ([]byte, []int) {
	return fileDescriptor_c11d10095315801c, []int{0}
}
func (m *TokenMetadata) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *TokenMetadata) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_TokenMetadata.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *TokenMetadata) XXX_Merge(src proto.Message) {
	xxx_messageInfo_TokenMetadata.Merge(m, src)
}
func (m *TokenMetadata) XXX_Size() int {
	return m.Size()
}
func (m *TokenMetadata) XXX_DiscardUnknown() {
	xxx_messageInfo_TokenMetadata.DiscardUnknown(m)
}

var xxx_messageInfo_TokenMetadata proto.InternalMessageInfo

func (m *TokenMetadata) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *TokenMetadata) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *TokenMetadata) GetRoles() []string {
	if m != nil {
		return m.Roles
	}
	return nil
}

func (m *TokenMetadata) GetIssuedAt() *types.Timestamp {
	if m != nil {
		return m.IssuedAt
	}
	return nil
}

func (m *TokenMetadata) GetExpiration() *types.Timestamp {
	if m != nil {
		return m.Expiration
	}
	return nil
}

func (m *TokenMetadata) GetRevoked() bool {
	if m != nil {
		return m.Revoked
	}
	return false
}

// Deprecated: Do not use.
func (m *TokenMetadata) GetRole() string {
	if m != nil {
		return m.Role
	}
	return ""
}

func (m *TokenMetadata) MessageClone() proto.Message {
	return m.Clone()
}
func (m *TokenMetadata) Clone() *TokenMetadata {
	if m == nil {
		return nil
	}
	cloned := new(TokenMetadata)
	*cloned = *m

	if m.Roles != nil {
		cloned.Roles = make([]string, len(m.Roles))
		copy(cloned.Roles, m.Roles)
	}
	cloned.IssuedAt = m.IssuedAt.Clone()
	cloned.Expiration = m.Expiration.Clone()
	return cloned
}

func init() {
	proto.RegisterType((*TokenMetadata)(nil), "storage.TokenMetadata")
}

func init() { proto.RegisterFile("storage/api_token.proto", fileDescriptor_c11d10095315801c) }

var fileDescriptor_c11d10095315801c = []byte{
	// 393 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x84, 0x92, 0xc1, 0x8e, 0x94, 0x40,
	0x10, 0x86, 0xed, 0x99, 0xd9, 0x9d, 0x99, 0x56, 0x2f, 0x9d, 0xcd, 0xda, 0x4b, 0x14, 0x08, 0x27,
	0x0e, 0x06, 0x12, 0xdd, 0xc4, 0x04, 0xe3, 0x61, 0x49, 0x3c, 0x78, 0xd0, 0x18, 0xb2, 0x1e, 0xd6,
	0x0b, 0xe9, 0x1d, 0x4a, 0xec, 0x30, 0xd0, 0x6c, 0x77, 0x63, 0xc6, 0xf7, 0xf0, 0xe0, 0x23, 0x79,
	0xf4, 0x09, 0x88, 0x19, 0xdf, 0x80, 0x27, 0x30, 0x74, 0x0f, 0x13, 0x6f, 0x7b, 0xab, 0xfa, 0xab,
	0xfe, 0x9f, 0xfa, 0x00, 0xfc, 0x44, 0x69, 0x21, 0x59, 0x09, 0x31, 0x6b, 0x79, 0xae, 0x45, 0x05,
	0x4d, 0xd4, 0x4a, 0xa1, 0x05, 0x59, 0x1e, 0x06, 0x8e, 0x57, 0x0a, 0x51, 0x6e, 0x21, 0x36, 0xf2,
	0x6d, 0xf7, 0x25, 0xd6, 0xbc, 0x06, 0xa5, 0x59, 0xdd, 0xda, 0x4d, 0xe7, 0xac, 0x14, 0xa5, 0x30,
	0x65, 0x3c, 0x56, 0x56, 0x0d, 0x7e, 0xcc, 0xf1, 0xe3, 0xeb, 0x31, 0xef, 0x3d, 0x68, 0x56, 0x30,
	0xcd, 0xc8, 0x53, 0x3c, 0xe3, 0x05, 0x45, 0x3e, 0x0a, 0xd7, 0xe9, 0xa3, 0xa1, 0xf7, 0x56, 0xea,
	0x6e, 0x9b, 0x04, 0x6d, 0x15, 0x64, 0x33, 0x5e, 0x90, 0x1a, 0x2f, 0x1a, 0x56, 0x03, 0x9d, 0x99,
	0xf9, 0xcd, 0xd0, 0x7b, 0x9f, 0x14, 0x30, 0xb9, 0xf9, 0x9a, 0x04, 0x57, 0x1f, 0xdf, 0xf9, 0x26,
	0xca, 0xff, 0xc0, 0x6a, 0x78, 0x3e, 0x1e, 0x06, 0x81, 0x6f, 0xdc, 0xbc, 0x29, 0x60, 0xf7, 0x66,
	0xc3, 0x34, 0x94, 0x42, 0x7e, 0x4f, 0xba, 0x86, 0xdf, 0x75, 0xf0, 0x7a, 0x0c, 0x4a, 0x8e, 0x40,
	0x2a, 0xb7, 0x72, 0x3e, 0xca, 0x41, 0x66, 0x1e, 0x43, 0xce, 0xf0, 0x89, 0x14, 0x5b, 0x50, 0x74,
	0xe9, 0xcf, 0xc3, 0x75, 0x66, 0x1b, 0xf2, 0x0a, 0xaf, 0xb9, 0x52, 0x1d, 0x14, 0x39, 0xd3, 0x74,
	0xe1, 0xa3, 0xf0, 0xe1, 0x0b, 0x27, 0xb2, 0xfc, 0xd1, 0xc4, 0x1f, 0x5d, 0x4f, 0xfc, 0xd9, 0xca,
	0x2e, 0x5f, 0x69, 0x72, 0x83, 0x31, 0xec, 0x5a, 0x2e, 0x99, 0xe6, 0xa2, 0xa1, 0x27, 0xf7, 0x39,
	0xd3, 0x67, 0x43, 0xef, 0x5d, 0x4c, 0x7c, 0x6f, 0x8f, 0xce, 0x03, 0x5b, 0xf6, 0x5f, 0x18, 0xb9,
	0xc4, 0x4b, 0x09, 0xdf, 0x44, 0x05, 0x05, 0x3d, 0xf5, 0x51, 0xb8, 0x4a, 0x9d, 0xa1, 0xf7, 0xce,
	0x27, 0x6f, 0x66, 0x47, 0x93, 0x71, 0x5a, 0x25, 0xe7, 0x78, 0x31, 0x22, 0xd1, 0xb9, 0x79, 0x9d,
	0x33, 0x8a, 0x32, 0xd3, 0xa7, 0x97, 0xbf, 0xf6, 0x2e, 0xfa, 0xbd, 0x77, 0xd1, 0x9f, 0xbd, 0x8b,
	0x7e, 0xfe, 0x75, 0x1f, 0xe0, 0x0b, 0x2e, 0x22, 0xa5, 0xd9, 0xa6, 0x92, 0x62, 0x67, 0x4f, 0x8d,
	0x0e, 0x9f, 0xfe, 0xf3, 0xf4, 0x0f, 0xdc, 0x9e, 0x1a, 0xfd, 0xe5, 0xbf, 0x00, 0x00, 0x00, 0xff,
	0xff, 0x29, 0xd6, 0xc0, 0xd8, 0x2e, 0x02, 0x00, 0x00,
}

func (m *TokenMetadata) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *TokenMetadata) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *TokenMetadata) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if len(m.Roles) > 0 {
		for iNdEx := len(m.Roles) - 1; iNdEx >= 0; iNdEx-- {
			i -= len(m.Roles[iNdEx])
			copy(dAtA[i:], m.Roles[iNdEx])
			i = encodeVarintApiToken(dAtA, i, uint64(len(m.Roles[iNdEx])))
			i--
			dAtA[i] = 0x3a
		}
	}
	if m.Revoked {
		i--
		if m.Revoked {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x30
	}
	if m.Expiration != nil {
		{
			size, err := m.Expiration.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintApiToken(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x2a
	}
	if m.IssuedAt != nil {
		{
			size, err := m.IssuedAt.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintApiToken(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x22
	}
	if len(m.Role) > 0 {
		i -= len(m.Role)
		copy(dAtA[i:], m.Role)
		i = encodeVarintApiToken(dAtA, i, uint64(len(m.Role)))
		i--
		dAtA[i] = 0x1a
	}
	if len(m.Name) > 0 {
		i -= len(m.Name)
		copy(dAtA[i:], m.Name)
		i = encodeVarintApiToken(dAtA, i, uint64(len(m.Name)))
		i--
		dAtA[i] = 0x12
	}
	if len(m.Id) > 0 {
		i -= len(m.Id)
		copy(dAtA[i:], m.Id)
		i = encodeVarintApiToken(dAtA, i, uint64(len(m.Id)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintApiToken(dAtA []byte, offset int, v uint64) int {
	offset -= sovApiToken(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *TokenMetadata) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Id)
	if l > 0 {
		n += 1 + l + sovApiToken(uint64(l))
	}
	l = len(m.Name)
	if l > 0 {
		n += 1 + l + sovApiToken(uint64(l))
	}
	l = len(m.Role)
	if l > 0 {
		n += 1 + l + sovApiToken(uint64(l))
	}
	if m.IssuedAt != nil {
		l = m.IssuedAt.Size()
		n += 1 + l + sovApiToken(uint64(l))
	}
	if m.Expiration != nil {
		l = m.Expiration.Size()
		n += 1 + l + sovApiToken(uint64(l))
	}
	if m.Revoked {
		n += 2
	}
	if len(m.Roles) > 0 {
		for _, s := range m.Roles {
			l = len(s)
			n += 1 + l + sovApiToken(uint64(l))
		}
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func sovApiToken(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozApiToken(x uint64) (n int) {
	return sovApiToken(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *TokenMetadata) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowApiToken
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
			return fmt.Errorf("proto: TokenMetadata: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: TokenMetadata: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Id", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowApiToken
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
				return ErrInvalidLengthApiToken
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthApiToken
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Id = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Name", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowApiToken
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
				return ErrInvalidLengthApiToken
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthApiToken
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Name = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Role", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowApiToken
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
				return ErrInvalidLengthApiToken
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthApiToken
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Role = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field IssuedAt", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowApiToken
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
				return ErrInvalidLengthApiToken
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthApiToken
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.IssuedAt == nil {
				m.IssuedAt = &types.Timestamp{}
			}
			if err := m.IssuedAt.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 5:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Expiration", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowApiToken
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
				return ErrInvalidLengthApiToken
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthApiToken
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Expiration == nil {
				m.Expiration = &types.Timestamp{}
			}
			if err := m.Expiration.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 6:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Revoked", wireType)
			}
			var v int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowApiToken
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			m.Revoked = bool(v != 0)
		case 7:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Roles", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowApiToken
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
				return ErrInvalidLengthApiToken
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthApiToken
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Roles = append(m.Roles, string(dAtA[iNdEx:postIndex]))
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipApiToken(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthApiToken
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
func skipApiToken(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowApiToken
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
					return 0, ErrIntOverflowApiToken
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
					return 0, ErrIntOverflowApiToken
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
				return 0, ErrInvalidLengthApiToken
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupApiToken
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthApiToken
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthApiToken        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowApiToken          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupApiToken = fmt.Errorf("proto: unexpected end of group")
)
