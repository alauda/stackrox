// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v4.22.0
// source: storage/image_component.proto

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

type ImageComponent struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id        string     `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"` // This field is composite id over name, version, and operating system.
	Name      string     `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	Version   string     `protobuf:"bytes,3,opt,name=version,proto3" json:"version,omitempty"`
	License   *License   `protobuf:"bytes,4,opt,name=license,proto3" json:"license,omitempty"`
	Priority  int64      `protobuf:"varint,5,opt,name=priority,proto3" json:"priority,omitempty"`
	Source    SourceType `protobuf:"varint,6,opt,name=source,proto3,enum=storage.SourceType" json:"source,omitempty"`
	RiskScore float32    `protobuf:"fixed32,7,opt,name=risk_score,json=riskScore,proto3" json:"risk_score,omitempty"`
	// Types that are assignable to SetTopCvss:
	//
	//	*ImageComponent_TopCvss
	SetTopCvss isImageComponent_SetTopCvss `protobuf_oneof:"set_top_cvss"`
	// Component version that fixes all the fixable vulnerabilities in this component.
	FixedBy         string `protobuf:"bytes,9,opt,name=fixed_by,json=fixedBy,proto3" json:"fixed_by,omitempty"`
	OperatingSystem string `protobuf:"bytes,10,opt,name=operating_system,json=operatingSystem,proto3" json:"operating_system,omitempty"`
}

func (x *ImageComponent) Reset() {
	*x = ImageComponent{}
	if protoimpl.UnsafeEnabled {
		mi := &file_storage_image_component_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ImageComponent) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ImageComponent) ProtoMessage() {}

func (x *ImageComponent) ProtoReflect() protoreflect.Message {
	mi := &file_storage_image_component_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ImageComponent.ProtoReflect.Descriptor instead.
func (*ImageComponent) Descriptor() ([]byte, []int) {
	return file_storage_image_component_proto_rawDescGZIP(), []int{0}
}

func (x *ImageComponent) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *ImageComponent) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *ImageComponent) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

func (x *ImageComponent) GetLicense() *License {
	if x != nil {
		return x.License
	}
	return nil
}

func (x *ImageComponent) GetPriority() int64 {
	if x != nil {
		return x.Priority
	}
	return 0
}

func (x *ImageComponent) GetSource() SourceType {
	if x != nil {
		return x.Source
	}
	return SourceType_OS
}

func (x *ImageComponent) GetRiskScore() float32 {
	if x != nil {
		return x.RiskScore
	}
	return 0
}

func (m *ImageComponent) GetSetTopCvss() isImageComponent_SetTopCvss {
	if m != nil {
		return m.SetTopCvss
	}
	return nil
}

func (x *ImageComponent) GetTopCvss() float32 {
	if x, ok := x.GetSetTopCvss().(*ImageComponent_TopCvss); ok {
		return x.TopCvss
	}
	return 0
}

func (x *ImageComponent) GetFixedBy() string {
	if x != nil {
		return x.FixedBy
	}
	return ""
}

func (x *ImageComponent) GetOperatingSystem() string {
	if x != nil {
		return x.OperatingSystem
	}
	return ""
}

type isImageComponent_SetTopCvss interface {
	isImageComponent_SetTopCvss()
}

type ImageComponent_TopCvss struct {
	TopCvss float32 `protobuf:"fixed32,8,opt,name=top_cvss,json=topCvss,proto3,oneof"`
}

func (*ImageComponent_TopCvss) isImageComponent_SetTopCvss() {}

var File_storage_image_component_proto protoreflect.FileDescriptor

var file_storage_image_component_proto_rawDesc = []byte{
	0x0a, 0x1d, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2f, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x5f,
	0x63, 0x6f, 0x6d, 0x70, 0x6f, 0x6e, 0x65, 0x6e, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x07, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x1a, 0x13, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67,
	0x65, 0x2f, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x0f, 0x74,
	0x6f, 0x6f, 0x6c, 0x73, 0x2f, 0x65, 0x78, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x8f,
	0x05, 0x0a, 0x0e, 0x49, 0x6d, 0x61, 0x67, 0x65, 0x43, 0x6f, 0x6d, 0x70, 0x6f, 0x6e, 0x65, 0x6e,
	0x74, 0x12, 0x42, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x32, 0x82,
	0xb5, 0x18, 0x2e, 0x73, 0x65, 0x61, 0x72, 0x63, 0x68, 0x3a, 0x22, 0x43, 0x6f, 0x6d, 0x70, 0x6f,
	0x6e, 0x65, 0x6e, 0x74, 0x20, 0x49, 0x44, 0x2c, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2c, 0x68, 0x69,
	0x64, 0x64, 0x65, 0x6e, 0x22, 0x20, 0x73, 0x71, 0x6c, 0x3a, 0x22, 0x70, 0x6b, 0x2c, 0x69, 0x64,
	0x22, 0x52, 0x02, 0x69, 0x64, 0x12, 0x30, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x42, 0x1c, 0x82, 0xb5, 0x18, 0x18, 0x73, 0x65, 0x61, 0x72, 0x63, 0x68, 0x3a,
	0x22, 0x43, 0x6f, 0x6d, 0x70, 0x6f, 0x6e, 0x65, 0x6e, 0x74, 0x2c, 0x73, 0x74, 0x6f, 0x72, 0x65,
	0x22, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x3e, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69,
	0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x42, 0x24, 0x82, 0xb5, 0x18, 0x20, 0x73, 0x65,
	0x61, 0x72, 0x63, 0x68, 0x3a, 0x22, 0x43, 0x6f, 0x6d, 0x70, 0x6f, 0x6e, 0x65, 0x6e, 0x74, 0x20,
	0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x2c, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x22, 0x52, 0x07,
	0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x2a, 0x0a, 0x07, 0x6c, 0x69, 0x63, 0x65, 0x6e,
	0x73, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61,
	0x67, 0x65, 0x2e, 0x4c, 0x69, 0x63, 0x65, 0x6e, 0x73, 0x65, 0x52, 0x07, 0x6c, 0x69, 0x63, 0x65,
	0x6e, 0x73, 0x65, 0x12, 0x47, 0x0a, 0x08, 0x70, 0x72, 0x69, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x18,
	0x05, 0x20, 0x01, 0x28, 0x03, 0x42, 0x2b, 0x82, 0xb5, 0x18, 0x27, 0x73, 0x65, 0x61, 0x72, 0x63,
	0x68, 0x3a, 0x22, 0x43, 0x6f, 0x6d, 0x70, 0x6f, 0x6e, 0x65, 0x6e, 0x74, 0x20, 0x52, 0x69, 0x73,
	0x6b, 0x20, 0x50, 0x72, 0x69, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x2c, 0x68, 0x69, 0x64, 0x64, 0x65,
	0x6e, 0x22, 0x52, 0x08, 0x70, 0x72, 0x69, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x12, 0x50, 0x0a, 0x06,
	0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x13, 0x2e, 0x73,
	0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x54, 0x79, 0x70,
	0x65, 0x42, 0x23, 0x82, 0xb5, 0x18, 0x1f, 0x73, 0x65, 0x61, 0x72, 0x63, 0x68, 0x3a, 0x22, 0x43,
	0x6f, 0x6d, 0x70, 0x6f, 0x6e, 0x65, 0x6e, 0x74, 0x20, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x2c,
	0x73, 0x74, 0x6f, 0x72, 0x65, 0x22, 0x52, 0x06, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x12, 0x47,
	0x0a, 0x0a, 0x72, 0x69, 0x73, 0x6b, 0x5f, 0x73, 0x63, 0x6f, 0x72, 0x65, 0x18, 0x07, 0x20, 0x01,
	0x28, 0x02, 0x42, 0x28, 0x82, 0xb5, 0x18, 0x24, 0x73, 0x65, 0x61, 0x72, 0x63, 0x68, 0x3a, 0x22,
	0x43, 0x6f, 0x6d, 0x70, 0x6f, 0x6e, 0x65, 0x6e, 0x74, 0x20, 0x52, 0x69, 0x73, 0x6b, 0x20, 0x53,
	0x63, 0x6f, 0x72, 0x65, 0x2c, 0x68, 0x69, 0x64, 0x64, 0x65, 0x6e, 0x22, 0x52, 0x09, 0x72, 0x69,
	0x73, 0x6b, 0x53, 0x63, 0x6f, 0x72, 0x65, 0x12, 0x42, 0x0a, 0x08, 0x74, 0x6f, 0x70, 0x5f, 0x63,
	0x76, 0x73, 0x73, 0x18, 0x08, 0x20, 0x01, 0x28, 0x02, 0x42, 0x25, 0x82, 0xb5, 0x18, 0x21, 0x73,
	0x65, 0x61, 0x72, 0x63, 0x68, 0x3a, 0x22, 0x43, 0x6f, 0x6d, 0x70, 0x6f, 0x6e, 0x65, 0x6e, 0x74,
	0x20, 0x54, 0x6f, 0x70, 0x20, 0x43, 0x56, 0x53, 0x53, 0x2c, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x22,
	0x48, 0x00, 0x52, 0x07, 0x74, 0x6f, 0x70, 0x43, 0x76, 0x73, 0x73, 0x12, 0x19, 0x0a, 0x08, 0x66,
	0x69, 0x78, 0x65, 0x64, 0x5f, 0x62, 0x79, 0x18, 0x09, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x66,
	0x69, 0x78, 0x65, 0x64, 0x42, 0x79, 0x12, 0x48, 0x0a, 0x10, 0x6f, 0x70, 0x65, 0x72, 0x61, 0x74,
	0x69, 0x6e, 0x67, 0x5f, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09,
	0x42, 0x1d, 0x82, 0xb5, 0x18, 0x19, 0x73, 0x65, 0x61, 0x72, 0x63, 0x68, 0x3a, 0x22, 0x4f, 0x70,
	0x65, 0x72, 0x61, 0x74, 0x69, 0x6e, 0x67, 0x20, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x22, 0x52,
	0x0f, 0x6f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6e, 0x67, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d,
	0x42, 0x0e, 0x0a, 0x0c, 0x73, 0x65, 0x74, 0x5f, 0x74, 0x6f, 0x70, 0x5f, 0x63, 0x76, 0x73, 0x73,
	0x42, 0x26, 0x0a, 0x19, 0x69, 0x6f, 0x2e, 0x73, 0x74, 0x61, 0x63, 0x6b, 0x72, 0x6f, 0x78, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x5a, 0x09, 0x2e,
	0x2f, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_storage_image_component_proto_rawDescOnce sync.Once
	file_storage_image_component_proto_rawDescData = file_storage_image_component_proto_rawDesc
)

func file_storage_image_component_proto_rawDescGZIP() []byte {
	file_storage_image_component_proto_rawDescOnce.Do(func() {
		file_storage_image_component_proto_rawDescData = protoimpl.X.CompressGZIP(file_storage_image_component_proto_rawDescData)
	})
	return file_storage_image_component_proto_rawDescData
}

var file_storage_image_component_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_storage_image_component_proto_goTypes = []interface{}{
	(*ImageComponent)(nil), // 0: storage.ImageComponent
	(*License)(nil),        // 1: storage.License
	(SourceType)(0),        // 2: storage.SourceType
}
var file_storage_image_component_proto_depIdxs = []int32{
	1, // 0: storage.ImageComponent.license:type_name -> storage.License
	2, // 1: storage.ImageComponent.source:type_name -> storage.SourceType
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_storage_image_component_proto_init() }
func file_storage_image_component_proto_init() {
	if File_storage_image_component_proto != nil {
		return
	}
	file_storage_image_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_storage_image_component_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ImageComponent); i {
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
	file_storage_image_component_proto_msgTypes[0].OneofWrappers = []interface{}{
		(*ImageComponent_TopCvss)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_storage_image_component_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_storage_image_component_proto_goTypes,
		DependencyIndexes: file_storage_image_component_proto_depIdxs,
		MessageInfos:      file_storage_image_component_proto_msgTypes,
	}.Build()
	File_storage_image_component_proto = out.File
	file_storage_image_component_proto_rawDesc = nil
	file_storage_image_component_proto_goTypes = nil
	file_storage_image_component_proto_depIdxs = nil
}
