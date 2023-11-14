// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v4.22.0
// source: storage/taints.proto

package storage

import (
	_ "./tools"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type TaintEffect int32

const (
	TaintEffect_UNKNOWN_TAINT_EFFECT            TaintEffect = 0
	TaintEffect_NO_SCHEDULE_TAINT_EFFECT        TaintEffect = 1
	TaintEffect_PREFER_NO_SCHEDULE_TAINT_EFFECT TaintEffect = 2
	TaintEffect_NO_EXECUTE_TAINT_EFFECT         TaintEffect = 3
)

// Enum value maps for TaintEffect.
var (
	TaintEffect_name = map[int32]string{
		0: "UNKNOWN_TAINT_EFFECT",
		1: "NO_SCHEDULE_TAINT_EFFECT",
		2: "PREFER_NO_SCHEDULE_TAINT_EFFECT",
		3: "NO_EXECUTE_TAINT_EFFECT",
	}
	TaintEffect_value = map[string]int32{
		"UNKNOWN_TAINT_EFFECT":            0,
		"NO_SCHEDULE_TAINT_EFFECT":        1,
		"PREFER_NO_SCHEDULE_TAINT_EFFECT": 2,
		"NO_EXECUTE_TAINT_EFFECT":         3,
	}
)

func (x TaintEffect) Enum() *TaintEffect {
	p := new(TaintEffect)
	*p = x
	return p
}

func (x TaintEffect) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (TaintEffect) Descriptor() protoreflect.EnumDescriptor {
	return file_storage_taints_proto_enumTypes[0].Descriptor()
}

func (TaintEffect) Type() protoreflect.EnumType {
	return &file_storage_taints_proto_enumTypes[0]
}

func (x TaintEffect) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use TaintEffect.Descriptor instead.
func (TaintEffect) EnumDescriptor() ([]byte, []int) {
	return file_storage_taints_proto_rawDescGZIP(), []int{0}
}

type Toleration_Operator int32

const (
	Toleration_TOLERATION_OPERATION_UNKNOWN Toleration_Operator = 0
	Toleration_TOLERATION_OPERATOR_EXISTS   Toleration_Operator = 1
	Toleration_TOLERATION_OPERATOR_EQUAL    Toleration_Operator = 2
)

// Enum value maps for Toleration_Operator.
var (
	Toleration_Operator_name = map[int32]string{
		0: "TOLERATION_OPERATION_UNKNOWN",
		1: "TOLERATION_OPERATOR_EXISTS",
		2: "TOLERATION_OPERATOR_EQUAL",
	}
	Toleration_Operator_value = map[string]int32{
		"TOLERATION_OPERATION_UNKNOWN": 0,
		"TOLERATION_OPERATOR_EXISTS":   1,
		"TOLERATION_OPERATOR_EQUAL":    2,
	}
)

func (x Toleration_Operator) Enum() *Toleration_Operator {
	p := new(Toleration_Operator)
	*p = x
	return p
}

func (x Toleration_Operator) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Toleration_Operator) Descriptor() protoreflect.EnumDescriptor {
	return file_storage_taints_proto_enumTypes[1].Descriptor()
}

func (Toleration_Operator) Type() protoreflect.EnumType {
	return &file_storage_taints_proto_enumTypes[1]
}

func (x Toleration_Operator) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Toleration_Operator.Descriptor instead.
func (Toleration_Operator) EnumDescriptor() ([]byte, []int) {
	return file_storage_taints_proto_rawDescGZIP(), []int{1, 0}
}

type Taint struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Key         string      `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	Value       string      `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
	TaintEffect TaintEffect `protobuf:"varint,3,opt,name=taint_effect,json=taintEffect,proto3,enum=storage.TaintEffect" json:"taint_effect,omitempty"`
}

func (x *Taint) Reset() {
	*x = Taint{}
	if protoimpl.UnsafeEnabled {
		mi := &file_storage_taints_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Taint) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Taint) ProtoMessage() {}

func (x *Taint) ProtoReflect() protoreflect.Message {
	mi := &file_storage_taints_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Taint.ProtoReflect.Descriptor instead.
func (*Taint) Descriptor() ([]byte, []int) {
	return file_storage_taints_proto_rawDescGZIP(), []int{0}
}

func (x *Taint) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (x *Taint) GetValue() string {
	if x != nil {
		return x.Value
	}
	return ""
}

func (x *Taint) GetTaintEffect() TaintEffect {
	if x != nil {
		return x.TaintEffect
	}
	return TaintEffect_UNKNOWN_TAINT_EFFECT
}

type Toleration struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Key         string              `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	Operator    Toleration_Operator `protobuf:"varint,2,opt,name=operator,proto3,enum=storage.Toleration_Operator" json:"operator,omitempty"`
	Value       string              `protobuf:"bytes,3,opt,name=value,proto3" json:"value,omitempty"`
	TaintEffect TaintEffect         `protobuf:"varint,4,opt,name=taint_effect,json=taintEffect,proto3,enum=storage.TaintEffect" json:"taint_effect,omitempty"`
}

func (x *Toleration) Reset() {
	*x = Toleration{}
	if protoimpl.UnsafeEnabled {
		mi := &file_storage_taints_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Toleration) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Toleration) ProtoMessage() {}

func (x *Toleration) ProtoReflect() protoreflect.Message {
	mi := &file_storage_taints_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Toleration.ProtoReflect.Descriptor instead.
func (*Toleration) Descriptor() ([]byte, []int) {
	return file_storage_taints_proto_rawDescGZIP(), []int{1}
}

func (x *Toleration) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (x *Toleration) GetOperator() Toleration_Operator {
	if x != nil {
		return x.Operator
	}
	return Toleration_TOLERATION_OPERATION_UNKNOWN
}

func (x *Toleration) GetValue() string {
	if x != nil {
		return x.Value
	}
	return ""
}

func (x *Toleration) GetTaintEffect() TaintEffect {
	if x != nil {
		return x.TaintEffect
	}
	return TaintEffect_UNKNOWN_TAINT_EFFECT
}

var File_storage_taints_proto protoreflect.FileDescriptor

var file_storage_taints_proto_rawDesc = []byte{
	0x0a, 0x14, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2f, 0x74, 0x61, 0x69, 0x6e, 0x74, 0x73,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x07, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x1a,
	0x0f, 0x74, 0x6f, 0x6f, 0x6c, 0x73, 0x2f, 0x65, 0x78, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x22, 0xb5, 0x01, 0x0a, 0x05, 0x54, 0x61, 0x69, 0x6e, 0x74, 0x12, 0x28, 0x0a, 0x03, 0x6b, 0x65,
	0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x16, 0x82, 0xb5, 0x18, 0x12, 0x73, 0x65, 0x61,
	0x72, 0x63, 0x68, 0x3a, 0x22, 0x54, 0x61, 0x69, 0x6e, 0x74, 0x20, 0x4b, 0x65, 0x79, 0x22, 0x52,
	0x03, 0x6b, 0x65, 0x79, 0x12, 0x2e, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x42, 0x18, 0x82, 0xb5, 0x18, 0x14, 0x73, 0x65, 0x61, 0x72, 0x63, 0x68, 0x3a,
	0x22, 0x54, 0x61, 0x69, 0x6e, 0x74, 0x20, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x22, 0x52, 0x05, 0x76,
	0x61, 0x6c, 0x75, 0x65, 0x12, 0x52, 0x0a, 0x0c, 0x74, 0x61, 0x69, 0x6e, 0x74, 0x5f, 0x65, 0x66,
	0x66, 0x65, 0x63, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x14, 0x2e, 0x73, 0x74, 0x6f,
	0x72, 0x61, 0x67, 0x65, 0x2e, 0x54, 0x61, 0x69, 0x6e, 0x74, 0x45, 0x66, 0x66, 0x65, 0x63, 0x74,
	0x42, 0x19, 0x82, 0xb5, 0x18, 0x15, 0x73, 0x65, 0x61, 0x72, 0x63, 0x68, 0x3a, 0x22, 0x54, 0x61,
	0x69, 0x6e, 0x74, 0x20, 0x45, 0x66, 0x66, 0x65, 0x63, 0x74, 0x22, 0x52, 0x0b, 0x74, 0x61, 0x69,
	0x6e, 0x74, 0x45, 0x66, 0x66, 0x65, 0x63, 0x74, 0x22, 0xd0, 0x02, 0x0a, 0x0a, 0x54, 0x6f, 0x6c,
	0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x2d, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x42, 0x1b, 0x82, 0xb5, 0x18, 0x17, 0x73, 0x65, 0x61, 0x72, 0x63, 0x68,
	0x3a, 0x22, 0x54, 0x6f, 0x6c, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x4b, 0x65, 0x79,
	0x22, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x38, 0x0a, 0x08, 0x6f, 0x70, 0x65, 0x72, 0x61, 0x74,
	0x6f, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x1c, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61,
	0x67, 0x65, 0x2e, 0x54, 0x6f, 0x6c, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x4f, 0x70,
	0x65, 0x72, 0x61, 0x74, 0x6f, 0x72, 0x52, 0x08, 0x6f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x6f, 0x72,
	0x12, 0x33, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x42,
	0x1d, 0x82, 0xb5, 0x18, 0x19, 0x73, 0x65, 0x61, 0x72, 0x63, 0x68, 0x3a, 0x22, 0x54, 0x6f, 0x6c,
	0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x22, 0x52, 0x05,
	0x76, 0x61, 0x6c, 0x75, 0x65, 0x12, 0x37, 0x0a, 0x0c, 0x74, 0x61, 0x69, 0x6e, 0x74, 0x5f, 0x65,
	0x66, 0x66, 0x65, 0x63, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x14, 0x2e, 0x73, 0x74,
	0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x54, 0x61, 0x69, 0x6e, 0x74, 0x45, 0x66, 0x66, 0x65, 0x63,
	0x74, 0x52, 0x0b, 0x74, 0x61, 0x69, 0x6e, 0x74, 0x45, 0x66, 0x66, 0x65, 0x63, 0x74, 0x22, 0x6b,
	0x0a, 0x08, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x6f, 0x72, 0x12, 0x20, 0x0a, 0x1c, 0x54, 0x4f,
	0x4c, 0x45, 0x52, 0x41, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x4f, 0x50, 0x45, 0x52, 0x41, 0x54, 0x49,
	0x4f, 0x4e, 0x5f, 0x55, 0x4e, 0x4b, 0x4e, 0x4f, 0x57, 0x4e, 0x10, 0x00, 0x12, 0x1e, 0x0a, 0x1a,
	0x54, 0x4f, 0x4c, 0x45, 0x52, 0x41, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x4f, 0x50, 0x45, 0x52, 0x41,
	0x54, 0x4f, 0x52, 0x5f, 0x45, 0x58, 0x49, 0x53, 0x54, 0x53, 0x10, 0x01, 0x12, 0x1d, 0x0a, 0x19,
	0x54, 0x4f, 0x4c, 0x45, 0x52, 0x41, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x4f, 0x50, 0x45, 0x52, 0x41,
	0x54, 0x4f, 0x52, 0x5f, 0x45, 0x51, 0x55, 0x41, 0x4c, 0x10, 0x02, 0x2a, 0x87, 0x01, 0x0a, 0x0b,
	0x54, 0x61, 0x69, 0x6e, 0x74, 0x45, 0x66, 0x66, 0x65, 0x63, 0x74, 0x12, 0x18, 0x0a, 0x14, 0x55,
	0x4e, 0x4b, 0x4e, 0x4f, 0x57, 0x4e, 0x5f, 0x54, 0x41, 0x49, 0x4e, 0x54, 0x5f, 0x45, 0x46, 0x46,
	0x45, 0x43, 0x54, 0x10, 0x00, 0x12, 0x1c, 0x0a, 0x18, 0x4e, 0x4f, 0x5f, 0x53, 0x43, 0x48, 0x45,
	0x44, 0x55, 0x4c, 0x45, 0x5f, 0x54, 0x41, 0x49, 0x4e, 0x54, 0x5f, 0x45, 0x46, 0x46, 0x45, 0x43,
	0x54, 0x10, 0x01, 0x12, 0x23, 0x0a, 0x1f, 0x50, 0x52, 0x45, 0x46, 0x45, 0x52, 0x5f, 0x4e, 0x4f,
	0x5f, 0x53, 0x43, 0x48, 0x45, 0x44, 0x55, 0x4c, 0x45, 0x5f, 0x54, 0x41, 0x49, 0x4e, 0x54, 0x5f,
	0x45, 0x46, 0x46, 0x45, 0x43, 0x54, 0x10, 0x02, 0x12, 0x1b, 0x0a, 0x17, 0x4e, 0x4f, 0x5f, 0x45,
	0x58, 0x45, 0x43, 0x55, 0x54, 0x45, 0x5f, 0x54, 0x41, 0x49, 0x4e, 0x54, 0x5f, 0x45, 0x46, 0x46,
	0x45, 0x43, 0x54, 0x10, 0x03, 0x42, 0x26, 0x0a, 0x19, 0x69, 0x6f, 0x2e, 0x73, 0x74, 0x61, 0x63,
	0x6b, 0x72, 0x6f, 0x78, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61,
	0x67, 0x65, 0x5a, 0x09, 0x2e, 0x2f, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_storage_taints_proto_rawDescOnce sync.Once
	file_storage_taints_proto_rawDescData = file_storage_taints_proto_rawDesc
)

func file_storage_taints_proto_rawDescGZIP() []byte {
	file_storage_taints_proto_rawDescOnce.Do(func() {
		file_storage_taints_proto_rawDescData = protoimpl.X.CompressGZIP(file_storage_taints_proto_rawDescData)
	})
	return file_storage_taints_proto_rawDescData
}

var file_storage_taints_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_storage_taints_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_storage_taints_proto_goTypes = []interface{}{
	(TaintEffect)(0),         // 0: storage.TaintEffect
	(Toleration_Operator)(0), // 1: storage.Toleration.Operator
	(*Taint)(nil),            // 2: storage.Taint
	(*Toleration)(nil),       // 3: storage.Toleration
}
var file_storage_taints_proto_depIdxs = []int32{
	0, // 0: storage.Taint.taint_effect:type_name -> storage.TaintEffect
	1, // 1: storage.Toleration.operator:type_name -> storage.Toleration.Operator
	0, // 2: storage.Toleration.taint_effect:type_name -> storage.TaintEffect
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_storage_taints_proto_init() }
func file_storage_taints_proto_init() {
	if File_storage_taints_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_storage_taints_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Taint); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_storage_taints_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Toleration); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_storage_taints_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_storage_taints_proto_goTypes,
		DependencyIndexes: file_storage_taints_proto_depIdxs,
		EnumInfos:         file_storage_taints_proto_enumTypes,
		MessageInfos:      file_storage_taints_proto_msgTypes,
	}.Build()
	File_storage_taints_proto = out.File
	file_storage_taints_proto_rawDesc = nil
	file_storage_taints_proto_goTypes = nil
	file_storage_taints_proto_depIdxs = nil
}
