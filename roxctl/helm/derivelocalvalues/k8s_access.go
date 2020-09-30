package derivelocalvalues

import (
	"context"
	"fmt"

	"github.com/stackrox/rox/pkg/set"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/util/jsonpath"
)

type k8sObjectDescription struct {
	k8sObjectDescriptionInterface
	warnings []string
}

type k8sObjectDescriptionInterface interface {
	get(context context.Context, kind string, name string) (*unstructured.Unstructured, error)
}

func (k *k8sObjectDescription) evaluate(context context.Context, kind string, name string, path string) interface{} {
	res, err := k.get(context, kind, name)
	if err != nil {
		k.warn("Failed to lookup resource %s/%s: %v", kind, name, err)
		return nil
	}
	return unstructuredLookup(kind, name, *res, path)
}

func (k *k8sObjectDescription) evaluateOrDefault(context context.Context, kind string, name string, path string, def interface{}) interface{} {
	res := k.evaluate(context, kind, name, path)
	if res == nil {
		res = def
	}
	return res
}

func (k *k8sObjectDescription) evaluateToObject(context context.Context, kind string, name string, jsonpath string, def map[string]interface{}) map[string]interface{} {
	var objStrings map[string]interface{}
	x := k.evaluateOrDefault(context, kind, name, jsonpath, def)
	switch obj := x.(type) {
	case map[interface{}]interface{}:
		objStrings = make(map[string]interface{})
		for k, v := range obj {
			s, ok := k.(string)
			if !ok {
				continue
			}
			objStrings[s] = v
		}

	case map[string]interface{}:
		objStrings = obj

	default:
		k.warn("Unexpected data type (%T) at JsonPath %q for resource %s/%s", x, jsonpath, kind, name)
		return def
	}

	return objStrings
}

func (k *k8sObjectDescription) evaluateToSlice(context context.Context, kind string, name string, jsonpath string, def []interface{}) []interface{} {
	x := k.evaluateOrDefault(context, kind, name, jsonpath, def)
	slice, ok := x.([]interface{})
	if !ok {
		k.warn("Unexpected data type (%T) at JsonPath %q for resource %s/%s", x, jsonpath, kind, name)
		return def
	}
	return slice
}

func (k *k8sObjectDescription) evaluateToSubObject(context context.Context, kind string, name string, jsonpath string, retainKeys []string, def map[string]interface{}) map[string]interface{} {
	var objStrings map[string]interface{}
	x := k.evaluate(context, kind, name, jsonpath)
	if isNil(x) {
		return def
	}

	switch obj := x.(type) {
	case map[interface{}]interface{}:
		objStrings = make(map[string]interface{})
		for k, v := range obj {
			s, ok := k.(string)
			if !ok {
				continue
			}
			objStrings[s] = v
		}
	case map[string]interface{}:
		objStrings = obj
	default:
		k.warn("Unexpected data type (%T) at JsonPath %q for resource %s/%s", x, jsonpath, kind, name)
		return def
	}

	// Remove any keys from object, which are not in retainKeys.
	retainKeysSet := set.NewStringSet(retainKeys...)
	for objKey := range objStrings {
		if !retainKeysSet.Contains(objKey) {
			delete(objStrings, objKey)
		}
	}

	return objStrings
}

func (k *k8sObjectDescription) evaluateToString(context context.Context, kind string, name string, jsonpath string, def string) string {
	x := k.evaluateOrDefault(context, kind, name, jsonpath, def)
	s, ok := x.(string)
	if !ok {
		k.warn("Unexpected data type (%T) at JsonPath %q for resource %s/%s", x, jsonpath, kind, name)
		return def
	}
	return s
}

func (k *k8sObjectDescription) evaluateToStringP(context context.Context, kind string, name string, jsonpath string) *string {
	s := k.evaluateToString(context, kind, name, jsonpath, "")
	if s == "" {
		return nil
	}
	return &s
}

func (k *k8sObjectDescription) evaluateToInt64(context context.Context, kind string, name string, jsonpath string, def int64) int64 {
	x := k.evaluateOrDefault(context, kind, name, jsonpath, def)
	switch i := x.(type) {
	case int:
		return int64(i)
	case int16:
		return int64(i)
	case int32:
		return int64(i)
	case int64:
		return i
	default:
		k.warn("Unexpected data type (%T) at JsonPath %q for resource %s/%s", x, jsonpath, kind, name)
		return def
	}
}

func (k *k8sObjectDescription) Exists(context context.Context, kind string, name string) bool {
	_, err := k.get(context, kind, name)
	return err == nil
}

func unstructuredLookup(kind string, name string, u unstructured.Unstructured, path string) interface{} {
	jp := jsonpath.New(fmt.Sprintf("unstructured Lookup for %s/%s", kind, name))
	err := jp.Parse(path)
	if err != nil {
		// This is a bug in the jsonpath description itself.
		panic(fmt.Sprintf("Error: Invalid json path %q", path))
	}

	vals, err := jp.FindResults(u.UnstructuredContent())
	if err != nil {
		return nil
	}

	if len(vals) == 0 || len(vals[0]) == 0 {
		return nil
	}
	return vals[0][0].Interface()
}

func newK8sObjectDescription(i k8sObjectDescriptionInterface) k8sObjectDescription {
	return k8sObjectDescription{k8sObjectDescriptionInterface: i, warnings: nil}
}

func (k *k8sObjectDescription) getWarnings() []string {
	return k.warnings
}

func (k *k8sObjectDescription) warn(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	k.warnings = append(k.warnings, msg)
}
