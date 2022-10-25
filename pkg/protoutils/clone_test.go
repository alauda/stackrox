package protoutils

import (
	"reflect"
	"testing"

	"github.com/stackrox/rox/generated/test"
	"github.com/stackrox/rox/pkg/transitional/protocompat/proto"
	"github.com/stackrox/rox/pkg/transitional/protocompat/types"
	"github.com/stretchr/testify/assert"
)

func getFilledStruct() *test.TestClone {
	return &test.TestClone{
		IntSlice:    []int32{1, 2, 3},
		StringSlice: []string{"1", "2", "3"},
		SubMessages: []*test.TestCloneSubMessage{
			{
				Int32:   1,
				String_: "1",
			},
			{
				Int32:   2,
				String_: "2",
			},
		},
		MessageMap: map[string]*test.TestCloneSubMessage{
			"1": {
				Int32:   1,
				String_: "1",
			},
			"2": {
				Int32:   2,
				String_: "2",
			},
		},
		StringMap: map[string]string{
			"1": "1a",
			"2": "2a",
		},
		EnumSlice: []test.TestClone_CloneEnum{test.TestClone_UNSET, test.TestClone_Val2},
		Ts:        types.TimestampNow(),
		Any: &types.Any{
			TypeUrl: "type url",
			Value:   []byte("123"),
		},
	}
}

func TestAutogeneratedClone(t *testing.T) {
	// All nil test case
	val := &test.TestClone{}
	assert.True(t, proto.Equal(val, val.CloneVT()))

	val = getFilledStruct()
	assert.Equal(t, val, val.CloneVT())

	val = getFilledStruct()
	cloned := val.CloneVT()
	val.IntSlice[0] = 100
	assert.False(t, proto.Equal(val, cloned))

	val = getFilledStruct()
	cloned = val.CloneVT()
	val.StringSlice[0] = "100"
	assert.False(t, proto.Equal(val, cloned))

	val = getFilledStruct()
	cloned = val.CloneVT()
	val.SubMessages[0].Int32 = 100
	assert.False(t, proto.Equal(val, cloned))

	val = getFilledStruct()
	cloned = val.CloneVT()
	delete(val.MessageMap, "1")
	assert.False(t, proto.Equal(val, cloned))

	val = getFilledStruct()
	cloned = val.CloneVT()
	delete(val.StringMap, "1")
	assert.False(t, proto.Equal(val, cloned))

	val = getFilledStruct()
	cloned = val.CloneVT()
	val.EnumSlice[0] = test.TestClone_Val1
	assert.False(t, proto.Equal(val, cloned))

	val = getFilledStruct()
	cloned = val.CloneVT()
	val.Ts.Seconds = 100000
	assert.False(t, proto.Equal(val, cloned))
}

func TestAutogeneratedCloneOneOfs(t *testing.T) {
	// All nil test case
	val := &test.TestClone{
		Primitive: &test.TestClone_Int32{
			Int32: 10,
		},
	}
	assert.True(t, proto.Equal(val, val.CloneVT()))

	val = &test.TestClone{
		Primitive: &test.TestClone_String_{
			String_: "10",
		},
	}
	assert.True(t, proto.Equal(val, val.CloneVT()))

	val = &test.TestClone{
		Primitive: &test.TestClone_Msg{
			Msg: &test.TestCloneSubMessage{
				Int32:   10,
				String_: "10",
			},
		},
	}
	assert.True(t, proto.Equal(val, val.CloneVT()))
}

func checkPointers(t *testing.T, orig, cloned reflect.Value) {
	origPtr := orig.Pointer()
	clonedPtr := cloned.Pointer()
	if origPtr == 0 && clonedPtr == 0 {
		return
	}
	assert.NotEqual(t, orig.Pointer(), cloned.Pointer())
}

func checkAliasRecursive(t *testing.T, orig, cloned reflect.Value) {
	switch orig.Kind() {
	case reflect.Array, reflect.Slice:
		checkPointers(t, orig, cloned)
		for i := 0; i < orig.Len(); i++ {
			checkAliasRecursive(t, orig.Index(i), cloned.Index(i))
		}
	case reflect.Interface:
		checkAliasRecursive(t, orig.Elem(), cloned.Elem())
	case reflect.Map:
		iter := orig.MapRange()
		for iter.Next() {
			checkAliasRecursive(t, iter.Value(), cloned.MapIndex(iter.Key()))
		}
	case reflect.Ptr:
		checkPointers(t, orig, cloned)
		checkAliasRecursive(t, orig.Elem(), cloned.Elem())
	case reflect.Struct:
		for i := 0; i < orig.NumField(); i++ {
			checkAliasRecursive(t, orig.Field(i), cloned.Field(i))
		}
	case reflect.UnsafePointer:
		checkPointers(t, orig, cloned)
	}
}

func TestCheckAliasing(t *testing.T) {
	obj := getFilledStruct()
	clonedObj := obj.CloneVT()

	checkAliasRecursive(t, reflect.ValueOf(obj), reflect.ValueOf(clonedObj))
}
