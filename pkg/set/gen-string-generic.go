// Code generated by genny. DO NOT EDIT.
// This file was automatically generated by genny.
// Any changes will be lost if this file is regenerated.
// see https://github.com/mauricelam/genny

package set

import (
	"sort"

	mapset "github.com/deckarep/golang-set"
)

// If you want to add a set for your custom type, simply add another go generate line along with the
// existing ones. If you're creating a set for a primitive type, you can follow the example of "string"
// and create the generated file in this package.
// Sometimes, you might need to create it in the same package where it is defined to avoid import cycles.
// The permission set is an example of how to do that.
// You can also specify the -imp command to specify additional imports in your generated file, if required.

// string represents a generic type that we want to have a set of.

// StringSet will get translated to generic sets.
// It uses mapset.Set as the underlying implementation, so it comes with a bunch
// of utility methods, and is thread-safe.
type StringSet struct {
	underlying mapset.Set
}

// Add adds an element of type string.
func (k StringSet) Add(i string) bool {
	if k.underlying == nil {
		k.underlying = mapset.NewSet()
	}

	return k.underlying.Add(i)
}

// Remove removes an element of type string.
func (k StringSet) Remove(i string) {
	if k.underlying != nil {
		k.underlying.Remove(i)
	}
}

// Contains returns whether the set contains an element of type string.
func (k StringSet) Contains(i string) bool {
	if k.underlying != nil {
		return k.underlying.Contains(i)
	}
	return false
}

// Cardinality returns the number of elements in the set.
func (k StringSet) Cardinality() int {
	if k.underlying != nil {
		return k.underlying.Cardinality()
	}
	return 0
}

// Difference returns a new set with all elements of k not in other.
func (k StringSet) Difference(other StringSet) StringSet {
	if k.underlying == nil {
		return StringSet{underlying: other.underlying}
	} else if other.underlying == nil {
		return StringSet{underlying: k.underlying}
	}

	return StringSet{underlying: k.underlying.Difference(other.underlying)}
}

// Intersect returns a new set with the intersection of the members of both sets.
func (k StringSet) Intersect(other StringSet) StringSet {
	if k.underlying != nil && other.underlying != nil {
		return StringSet{underlying: k.underlying.Intersect(other.underlying)}
	}
	return StringSet{}
}

// Union returns a new set with the union of the members of both sets.
func (k StringSet) Union(other StringSet) StringSet {
	if k.underlying == nil {
		return StringSet{underlying: other.underlying}
	} else if other.underlying == nil {
		return StringSet{underlying: k.underlying}
	}

	return StringSet{underlying: k.underlying.Union(other.underlying)}
}

// Equal returns a bool if the sets are equal
func (k StringSet) Equal(other StringSet) bool {
	if k.underlying == nil && other.underlying == nil {
		return true
	}
	if k.underlying == nil || other.underlying == nil {
		return false
	}
	return k.underlying.Equal(other.underlying)
}

// AsSlice returns a slice of the elements in the set. The order is unspecified.
func (k StringSet) AsSlice() []string {
	if k.underlying == nil {
		return nil
	}
	elems := make([]string, 0, k.Cardinality())
	for elem := range k.underlying.Iter() {
		elems = append(elems, elem.(string))
	}
	return elems
}

// AsSortedSlice returns a slice of the elements in the set, sorted using the passed less function.
func (k StringSet) AsSortedSlice(less func(i, j string) bool) []string {
	slice := k.AsSlice()
	if len(slice) < 2 {
		return slice
	}
	// Since we're generating the code, we might as well use sort.Sort
	// and avoid paying the reflection penalty of sort.Slice.
	sortable := &sortablestringSlice{slice: slice, less: less}
	sort.Sort(sortable)
	return sortable.slice
}

// IsInitialized returns whether the set has been initialized
func (k StringSet) IsInitialized() bool {
	return k.underlying != nil
}

// NewStringSet returns a new set with the given key type.
func NewStringSet(initial ...string) StringSet {
	k := StringSet{underlying: mapset.NewSet()}
	for _, elem := range initial {
		k.Add(elem)
	}
	return k
}

type sortablestringSlice struct {
	slice []string
	less  func(i, j string) bool
}

func (s *sortablestringSlice) Len() int {
	return len(s.slice)
}

func (s *sortablestringSlice) Less(i, j int) bool {
	return s.less(s.slice[i], s.slice[j])
}

func (s *sortablestringSlice) Swap(i, j int) {
	s.slice[j], s.slice[i] = s.slice[i], s.slice[j]
}
