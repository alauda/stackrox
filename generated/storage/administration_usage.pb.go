// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v4.22.0
// source: storage/administration_usage.proto

package storage

import (
	_ "./tools"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// SecuredUnits represents a record of an aggregated secured clusters usage
// metrics. The metrics are aggregated periodically, and put into the database.
type SecuredUnits struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// id is not used to retrieve data, but serves mostly for compatibility with
	// the current implementation of the query generator.
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	// timestamp stores the moment at which the values of the metrics below are
	// aggregated.
	Timestamp *timestamppb.Timestamp `protobuf:"bytes,2,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	// num_nodes is the maximum number of secured nodes, observed across all
	// registered clusters during last aggregation period.
	NumNodes int64 `protobuf:"varint,3,opt,name=num_nodes,json=numNodes,proto3" json:"num_nodes,omitempty"`
	// num_cpu_units is the maximum number of secured CPU units (which are the
	// units reported by Kubernetes), observed across all registered clusters
	// during last aggregation period.
	NumCpuUnits int64 `protobuf:"varint,4,opt,name=num_cpu_units,json=numCpuUnits,proto3" json:"num_cpu_units,omitempty"`
}

func (x *SecuredUnits) Reset() {
	*x = SecuredUnits{}
	if protoimpl.UnsafeEnabled {
		mi := &file_storage_administration_usage_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SecuredUnits) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SecuredUnits) ProtoMessage() {}

func (x *SecuredUnits) ProtoReflect() protoreflect.Message {
	mi := &file_storage_administration_usage_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SecuredUnits.ProtoReflect.Descriptor instead.
func (*SecuredUnits) Descriptor() ([]byte, []int) {
	return file_storage_administration_usage_proto_rawDescGZIP(), []int{0}
}

func (x *SecuredUnits) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *SecuredUnits) GetTimestamp() *timestamppb.Timestamp {
	if x != nil {
		return x.Timestamp
	}
	return nil
}

func (x *SecuredUnits) GetNumNodes() int64 {
	if x != nil {
		return x.NumNodes
	}
	return 0
}

func (x *SecuredUnits) GetNumCpuUnits() int64 {
	if x != nil {
		return x.NumCpuUnits
	}
	return 0
}

var File_storage_administration_usage_proto protoreflect.FileDescriptor

var file_storage_administration_usage_proto_rawDesc = []byte{
	0x0a, 0x22, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2f, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x69,
	0x73, 0x74, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x75, 0x73, 0x61, 0x67, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x07, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x1a, 0x1f, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74,
	0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x0f,
	0x74, 0x6f, 0x6f, 0x6c, 0x73, 0x2f, 0x65, 0x78, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0xd7, 0x02, 0x0a, 0x0c, 0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x64, 0x55, 0x6e, 0x69, 0x74, 0x73,
	0x12, 0x27, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x17, 0x82, 0xb5,
	0x18, 0x13, 0x73, 0x71, 0x6c, 0x3a, 0x22, 0x70, 0x6b, 0x2c, 0x74, 0x79, 0x70, 0x65, 0x28, 0x75,
	0x75, 0x69, 0x64, 0x29, 0x22, 0x52, 0x02, 0x69, 0x64, 0x12, 0x79, 0x0a, 0x09, 0x74, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54,
	0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x42, 0x3f, 0x82, 0xb5, 0x18, 0x3b, 0x73, 0x71,
	0x6c, 0x3a, 0x22, 0x75, 0x6e, 0x69, 0x71, 0x75, 0x65, 0x22, 0x20, 0x73, 0x65, 0x61, 0x72, 0x63,
	0x68, 0x3a, 0x22, 0x41, 0x64, 0x6d, 0x69, 0x6e, 0x69, 0x73, 0x74, 0x72, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x20, 0x55, 0x73, 0x61, 0x67, 0x65, 0x20, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d,
	0x70, 0x2c, 0x68, 0x69, 0x64, 0x64, 0x65, 0x6e, 0x22, 0x52, 0x09, 0x74, 0x69, 0x6d, 0x65, 0x73,
	0x74, 0x61, 0x6d, 0x70, 0x12, 0x4b, 0x0a, 0x09, 0x6e, 0x75, 0x6d, 0x5f, 0x6e, 0x6f, 0x64, 0x65,
	0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x03, 0x42, 0x2e, 0x82, 0xb5, 0x18, 0x2a, 0x73, 0x65, 0x61,
	0x72, 0x63, 0x68, 0x3a, 0x22, 0x41, 0x64, 0x6d, 0x69, 0x6e, 0x69, 0x73, 0x74, 0x72, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x20, 0x55, 0x73, 0x61, 0x67, 0x65, 0x20, 0x4e, 0x6f, 0x64, 0x65, 0x73, 0x2c,
	0x68, 0x69, 0x64, 0x64, 0x65, 0x6e, 0x22, 0x52, 0x08, 0x6e, 0x75, 0x6d, 0x4e, 0x6f, 0x64, 0x65,
	0x73, 0x12, 0x56, 0x0a, 0x0d, 0x6e, 0x75, 0x6d, 0x5f, 0x63, 0x70, 0x75, 0x5f, 0x75, 0x6e, 0x69,
	0x74, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x03, 0x42, 0x32, 0x82, 0xb5, 0x18, 0x2e, 0x73, 0x65,
	0x61, 0x72, 0x63, 0x68, 0x3a, 0x22, 0x41, 0x64, 0x6d, 0x69, 0x6e, 0x69, 0x73, 0x74, 0x72, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x20, 0x55, 0x73, 0x61, 0x67, 0x65, 0x20, 0x43, 0x50, 0x55, 0x20, 0x55,
	0x6e, 0x69, 0x74, 0x73, 0x2c, 0x68, 0x69, 0x64, 0x64, 0x65, 0x6e, 0x22, 0x52, 0x0b, 0x6e, 0x75,
	0x6d, 0x43, 0x70, 0x75, 0x55, 0x6e, 0x69, 0x74, 0x73, 0x42, 0x26, 0x0a, 0x19, 0x69, 0x6f, 0x2e,
	0x73, 0x74, 0x61, 0x63, 0x6b, 0x72, 0x6f, 0x78, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x73,
	0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x5a, 0x09, 0x2e, 0x2f, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67,
	0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_storage_administration_usage_proto_rawDescOnce sync.Once
	file_storage_administration_usage_proto_rawDescData = file_storage_administration_usage_proto_rawDesc
)

func file_storage_administration_usage_proto_rawDescGZIP() []byte {
	file_storage_administration_usage_proto_rawDescOnce.Do(func() {
		file_storage_administration_usage_proto_rawDescData = protoimpl.X.CompressGZIP(file_storage_administration_usage_proto_rawDescData)
	})
	return file_storage_administration_usage_proto_rawDescData
}

var file_storage_administration_usage_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_storage_administration_usage_proto_goTypes = []interface{}{
	(*SecuredUnits)(nil),          // 0: storage.SecuredUnits
	(*timestamppb.Timestamp)(nil), // 1: google.protobuf.Timestamp
}
var file_storage_administration_usage_proto_depIdxs = []int32{
	1, // 0: storage.SecuredUnits.timestamp:type_name -> google.protobuf.Timestamp
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_storage_administration_usage_proto_init() }
func file_storage_administration_usage_proto_init() {
	if File_storage_administration_usage_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_storage_administration_usage_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SecuredUnits); i {
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
			RawDescriptor: file_storage_administration_usage_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_storage_administration_usage_proto_goTypes,
		DependencyIndexes: file_storage_administration_usage_proto_depIdxs,
		MessageInfos:      file_storage_administration_usage_proto_msgTypes,
	}.Build()
	File_storage_administration_usage_proto = out.File
	file_storage_administration_usage_proto_rawDesc = nil
	file_storage_administration_usage_proto_goTypes = nil
	file_storage_administration_usage_proto_depIdxs = nil
}
