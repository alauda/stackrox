// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v4.22.0
// source: storage/service_account.proto

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

// Any properties of an individual service account.
// (regardless of time, scope, or context)
// ////////////////////////////////////////
type ServiceAccount struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id               string                 `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Name             string                 `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	Namespace        string                 `protobuf:"bytes,3,opt,name=namespace,proto3" json:"namespace,omitempty"`
	ClusterName      string                 `protobuf:"bytes,4,opt,name=cluster_name,json=clusterName,proto3" json:"cluster_name,omitempty"`
	ClusterId        string                 `protobuf:"bytes,5,opt,name=cluster_id,json=clusterId,proto3" json:"cluster_id,omitempty"`
	Labels           map[string]string      `protobuf:"bytes,6,rep,name=labels,proto3" json:"labels,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	Annotations      map[string]string      `protobuf:"bytes,7,rep,name=annotations,proto3" json:"annotations,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	CreatedAt        *timestamppb.Timestamp `protobuf:"bytes,8,opt,name=created_at,json=createdAt,proto3" json:"created_at,omitempty"`
	AutomountToken   bool                   `protobuf:"varint,9,opt,name=automount_token,json=automountToken,proto3" json:"automount_token,omitempty"`
	Secrets          []string               `protobuf:"bytes,10,rep,name=secrets,proto3" json:"secrets,omitempty"`
	ImagePullSecrets []string               `protobuf:"bytes,11,rep,name=image_pull_secrets,json=imagePullSecrets,proto3" json:"image_pull_secrets,omitempty"`
}

func (x *ServiceAccount) Reset() {
	*x = ServiceAccount{}
	if protoimpl.UnsafeEnabled {
		mi := &file_storage_service_account_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ServiceAccount) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ServiceAccount) ProtoMessage() {}

func (x *ServiceAccount) ProtoReflect() protoreflect.Message {
	mi := &file_storage_service_account_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ServiceAccount.ProtoReflect.Descriptor instead.
func (*ServiceAccount) Descriptor() ([]byte, []int) {
	return file_storage_service_account_proto_rawDescGZIP(), []int{0}
}

func (x *ServiceAccount) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *ServiceAccount) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *ServiceAccount) GetNamespace() string {
	if x != nil {
		return x.Namespace
	}
	return ""
}

func (x *ServiceAccount) GetClusterName() string {
	if x != nil {
		return x.ClusterName
	}
	return ""
}

func (x *ServiceAccount) GetClusterId() string {
	if x != nil {
		return x.ClusterId
	}
	return ""
}

func (x *ServiceAccount) GetLabels() map[string]string {
	if x != nil {
		return x.Labels
	}
	return nil
}

func (x *ServiceAccount) GetAnnotations() map[string]string {
	if x != nil {
		return x.Annotations
	}
	return nil
}

func (x *ServiceAccount) GetCreatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.CreatedAt
	}
	return nil
}

func (x *ServiceAccount) GetAutomountToken() bool {
	if x != nil {
		return x.AutomountToken
	}
	return false
}

func (x *ServiceAccount) GetSecrets() []string {
	if x != nil {
		return x.Secrets
	}
	return nil
}

func (x *ServiceAccount) GetImagePullSecrets() []string {
	if x != nil {
		return x.ImagePullSecrets
	}
	return nil
}

var File_storage_service_account_proto protoreflect.FileDescriptor

var file_storage_service_account_proto_rawDesc = []byte{
	0x0a, 0x1d, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x5f, 0x61, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x07, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74,
	0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x0f, 0x74, 0x6f, 0x6f, 0x6c, 0x73,
	0x2f, 0x65, 0x78, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xbf, 0x06, 0x0a, 0x0e, 0x53,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x41, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x27, 0x0a,
	0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x17, 0x82, 0xb5, 0x18, 0x13, 0x73,
	0x71, 0x6c, 0x3a, 0x22, 0x70, 0x6b, 0x2c, 0x74, 0x79, 0x70, 0x65, 0x28, 0x75, 0x75, 0x69, 0x64,
	0x29, 0x22, 0x52, 0x02, 0x69, 0x64, 0x12, 0x36, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x42, 0x22, 0x82, 0xb5, 0x18, 0x1e, 0x73, 0x65, 0x61, 0x72, 0x63, 0x68,
	0x3a, 0x22, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x20, 0x41, 0x63, 0x63, 0x6f, 0x75, 0x6e,
	0x74, 0x2c, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x22, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x3a,
	0x0a, 0x09, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x09, 0x42, 0x1c, 0x82, 0xb5, 0x18, 0x18, 0x73, 0x65, 0x61, 0x72, 0x63, 0x68, 0x3a, 0x22, 0x4e,
	0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x2c, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x22, 0x52,
	0x09, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x12, 0x3d, 0x0a, 0x0c, 0x63, 0x6c,
	0x75, 0x73, 0x74, 0x65, 0x72, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09,
	0x42, 0x1a, 0x82, 0xb5, 0x18, 0x16, 0x73, 0x65, 0x61, 0x72, 0x63, 0x68, 0x3a, 0x22, 0x43, 0x6c,
	0x75, 0x73, 0x74, 0x65, 0x72, 0x2c, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x22, 0x52, 0x0b, 0x63, 0x6c,
	0x75, 0x73, 0x74, 0x65, 0x72, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x54, 0x0a, 0x0a, 0x63, 0x6c, 0x75,
	0x73, 0x74, 0x65, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x42, 0x35, 0x82,
	0xb5, 0x18, 0x31, 0x73, 0x65, 0x61, 0x72, 0x63, 0x68, 0x3a, 0x22, 0x43, 0x6c, 0x75, 0x73, 0x74,
	0x65, 0x72, 0x20, 0x49, 0x44, 0x2c, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2c, 0x68, 0x69, 0x64, 0x64,
	0x65, 0x6e, 0x22, 0x20, 0x73, 0x71, 0x6c, 0x3a, 0x22, 0x74, 0x79, 0x70, 0x65, 0x28, 0x75, 0x75,
	0x69, 0x64, 0x29, 0x22, 0x52, 0x09, 0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x49, 0x64, 0x12,
	0x5f, 0x0a, 0x06, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x18, 0x06, 0x20, 0x03, 0x28, 0x0b, 0x32,
	0x23, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x41, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x2e, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x45,
	0x6e, 0x74, 0x72, 0x79, 0x42, 0x22, 0x82, 0xb5, 0x18, 0x1e, 0x73, 0x65, 0x61, 0x72, 0x63, 0x68,
	0x3a, 0x22, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x20, 0x41, 0x63, 0x63, 0x6f, 0x75, 0x6e,
	0x74, 0x20, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x22, 0x52, 0x06, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x73,
	0x12, 0x73, 0x0a, 0x0b, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18,
	0x07, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x28, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e,
	0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x41, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x2e, 0x41,
	0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x42,
	0x27, 0x82, 0xb5, 0x18, 0x23, 0x73, 0x65, 0x61, 0x72, 0x63, 0x68, 0x3a, 0x22, 0x53, 0x65, 0x72,
	0x76, 0x69, 0x63, 0x65, 0x20, 0x41, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x20, 0x41, 0x6e, 0x6e,
	0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0x52, 0x0b, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x39, 0x0a, 0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64,
	0x5f, 0x61, 0x74, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65,
	0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74,
	0x12, 0x27, 0x0a, 0x0f, 0x61, 0x75, 0x74, 0x6f, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x5f, 0x74, 0x6f,
	0x6b, 0x65, 0x6e, 0x18, 0x09, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0e, 0x61, 0x75, 0x74, 0x6f, 0x6d,
	0x6f, 0x75, 0x6e, 0x74, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x18, 0x0a, 0x07, 0x73, 0x65, 0x63,
	0x72, 0x65, 0x74, 0x73, 0x18, 0x0a, 0x20, 0x03, 0x28, 0x09, 0x52, 0x07, 0x73, 0x65, 0x63, 0x72,
	0x65, 0x74, 0x73, 0x12, 0x2c, 0x0a, 0x12, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x5f, 0x70, 0x75, 0x6c,
	0x6c, 0x5f, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x73, 0x18, 0x0b, 0x20, 0x03, 0x28, 0x09, 0x52,
	0x10, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x50, 0x75, 0x6c, 0x6c, 0x53, 0x65, 0x63, 0x72, 0x65, 0x74,
	0x73, 0x1a, 0x39, 0x0a, 0x0b, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79,
	0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b,
	0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x1a, 0x3e, 0x0a, 0x10,
	0x41, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79,
	0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b,
	0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x42, 0x26, 0x0a, 0x19,
	0x69, 0x6f, 0x2e, 0x73, 0x74, 0x61, 0x63, 0x6b, 0x72, 0x6f, 0x78, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x5a, 0x09, 0x2e, 0x2f, 0x73, 0x74, 0x6f,
	0x72, 0x61, 0x67, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_storage_service_account_proto_rawDescOnce sync.Once
	file_storage_service_account_proto_rawDescData = file_storage_service_account_proto_rawDesc
)

func file_storage_service_account_proto_rawDescGZIP() []byte {
	file_storage_service_account_proto_rawDescOnce.Do(func() {
		file_storage_service_account_proto_rawDescData = protoimpl.X.CompressGZIP(file_storage_service_account_proto_rawDescData)
	})
	return file_storage_service_account_proto_rawDescData
}

var file_storage_service_account_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_storage_service_account_proto_goTypes = []interface{}{
	(*ServiceAccount)(nil),        // 0: storage.ServiceAccount
	nil,                           // 1: storage.ServiceAccount.LabelsEntry
	nil,                           // 2: storage.ServiceAccount.AnnotationsEntry
	(*timestamppb.Timestamp)(nil), // 3: google.protobuf.Timestamp
}
var file_storage_service_account_proto_depIdxs = []int32{
	1, // 0: storage.ServiceAccount.labels:type_name -> storage.ServiceAccount.LabelsEntry
	2, // 1: storage.ServiceAccount.annotations:type_name -> storage.ServiceAccount.AnnotationsEntry
	3, // 2: storage.ServiceAccount.created_at:type_name -> google.protobuf.Timestamp
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_storage_service_account_proto_init() }
func file_storage_service_account_proto_init() {
	if File_storage_service_account_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_storage_service_account_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ServiceAccount); i {
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
			RawDescriptor: file_storage_service_account_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_storage_service_account_proto_goTypes,
		DependencyIndexes: file_storage_service_account_proto_depIdxs,
		MessageInfos:      file_storage_service_account_proto_msgTypes,
	}.Build()
	File_storage_service_account_proto = out.File
	file_storage_service_account_proto_rawDesc = nil
	file_storage_service_account_proto_goTypes = nil
	file_storage_service_account_proto_depIdxs = nil
}
