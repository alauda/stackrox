// Code generated by genny. DO NOT EDIT.
// This file was automatically generated by genny.
// Any changes will be lost if this file is regenerated.
// see https://github.com/mauricelam/genny

package set

import "github.com/stackrox/rox/generated/api/v1"
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

// v1.SearchCategory represents a generic type that we want to have a set of.

// V1SearchCategorySet will get translated to generic sets.
// It uses mapset.Set as the underlying implementation, so it comes with a bunch
// of utility methods, and is thread-safe.
type V1SearchCategorySet struct {
	underlying mapset.Set
}

// Add adds an element of type v1.SearchCategory.
func (k V1SearchCategorySet) Add(i v1.SearchCategory) bool {
	if k.underlying == nil {
		k.underlying = mapset.NewSet()
	}

	return k.underlying.Add(i)
}

// Remove removes an element of type v1.SearchCategory.
func (k V1SearchCategorySet) Remove(i v1.SearchCategory) {
	if k.underlying != nil {
		k.underlying.Remove(i)
	}
}

// Contains returns whether the set contains an element of type v1.SearchCategory.
func (k V1SearchCategorySet) Contains(i v1.SearchCategory) bool {
	if k.underlying != nil {
		return k.underlying.Contains(i)
	}
	return false
}

// Cardinality returns the number of elements in the set.
func (k V1SearchCategorySet) Cardinality() int {
	if k.underlying != nil {
		return k.underlying.Cardinality()
	}
	return 0
}

// Difference returns a new set with all elements of k not in other.
func (k V1SearchCategorySet) Difference(other V1SearchCategorySet) V1SearchCategorySet {
	if k.underlying == nil {
		return V1SearchCategorySet{underlying: other.underlying}
	} else if other.underlying == nil {
		return V1SearchCategorySet{underlying: k.underlying}
	}

	return V1SearchCategorySet{underlying: k.underlying.Difference(other.underlying)}
}

// Intersect returns a new set with the intersection of the members of both sets.
func (k V1SearchCategorySet) Intersect(other V1SearchCategorySet) V1SearchCategorySet {
	if k.underlying != nil && other.underlying != nil {
		return V1SearchCategorySet{underlying: k.underlying.Intersect(other.underlying)}
	}
	return V1SearchCategorySet{}
}

// Union returns a new set with the union of the members of both sets.
func (k V1SearchCategorySet) Union(other V1SearchCategorySet) V1SearchCategorySet {
	if k.underlying == nil {
		return V1SearchCategorySet{underlying: other.underlying}
	} else if other.underlying == nil {
		return V1SearchCategorySet{underlying: k.underlying}
	}

	return V1SearchCategorySet{underlying: k.underlying.Union(other.underlying)}
}

// Equal returns a bool if the sets are equal
func (k V1SearchCategorySet) Equal(other V1SearchCategorySet) bool {
	if k.underlying == nil && other.underlying == nil {
		return true
	}
	if k.underlying == nil || other.underlying == nil {
		return false
	}
	return k.underlying.Equal(other.underlying)
}

// AsSlice returns a slice of the elements in the set. The order is unspecified.
func (k V1SearchCategorySet) AsSlice() []v1.SearchCategory {
	if k.underlying == nil {
		return nil
	}
	elems := make([]v1.SearchCategory, 0, k.Cardinality())
	for elem := range k.underlying.Iter() {
		elems = append(elems, elem.(v1.SearchCategory))
	}
	return elems
}

// AsSortedSlice returns a slice of the elements in the set, sorted using the passed less function.
func (k V1SearchCategorySet) AsSortedSlice(less func(i, j v1.SearchCategory) bool) []v1.SearchCategory {
	slice := k.AsSlice()
	if len(slice) < 2 {
		return slice
	}
	// Since we're generating the code, we might as well use sort.Sort
	// and avoid paying the reflection penalty of sort.Slice.
	sortable := &sortablev1SearchCategorySlice{slice: slice, less: less}
	sort.Sort(sortable)
	return sortable.slice
}

// IsInitialized returns whether the set has been initialized
func (k V1SearchCategorySet) IsInitialized() bool {
	return k.underlying != nil
}

// Iter returns a range of elements you can iterate over.
// Note that in most cases, this is actually slower than pulling out a slice
// and ranging over that.
// NOTE THAT YOU MUST DRAIN THE RETURNED CHANNEL, OR THE SET WILL BE DEADLOCKED FOREVER.
func (k V1SearchCategorySet) Iter() <-chan v1.SearchCategory {
	ch := make(chan v1.SearchCategory)
	if k.underlying != nil {
		go func() {
			for elem := range k.underlying.Iter() {
				ch <- elem.(v1.SearchCategory)
			}
			close(ch)
		}()
	} else {
		close(ch)
	}
	return ch
}

// Freeze returns a new, frozen version of the set.
func (k V1SearchCategorySet) Freeze() FrozenV1SearchCategorySet {
	return NewFrozenV1SearchCategorySet(k.AsSlice()...)
}

// NewV1SearchCategorySet returns a new set with the given key type.
func NewV1SearchCategorySet(initial ...v1.SearchCategory) V1SearchCategorySet {
	k := V1SearchCategorySet{underlying: mapset.NewSet()}
	for _, elem := range initial {
		k.Add(elem)
	}
	return k
}

type sortablev1SearchCategorySlice struct {
	slice []v1.SearchCategory
	less  func(i, j v1.SearchCategory) bool
}

func (s *sortablev1SearchCategorySlice) Len() int {
	return len(s.slice)
}

func (s *sortablev1SearchCategorySlice) Less(i, j int) bool {
	return s.less(s.slice[i], s.slice[j])
}

func (s *sortablev1SearchCategorySlice) Swap(i, j int) {
	s.slice[j], s.slice[i] = s.slice[i], s.slice[j]
}

// A FrozenV1SearchCategorySet is a frozen set of v1.SearchCategory elements, which
// cannot be modified after creation. This allows users to use it as if it were
// a "const" data structure, and also makes it slightly more optimal since
// we don't have to lock accesses to it.
type FrozenV1SearchCategorySet struct {
	underlying map[v1.SearchCategory]struct{}
}

// NewFrozenV1SearchCategorySetFromChan returns a new frozen set from the provided channel.
// It drains the channel.
// This can be useful to avoid unnecessary slice allocations.
func NewFrozenV1SearchCategorySetFromChan(elementC <-chan v1.SearchCategory) FrozenV1SearchCategorySet {
	underlying := make(map[v1.SearchCategory]struct{})
	for elem := range elementC {
		underlying[elem] = struct{}{}
	}
	return FrozenV1SearchCategorySet{
		underlying: underlying,
	}
}

// NewFrozenV1SearchCategorySet returns a new frozen set with the provided elements.
func NewFrozenV1SearchCategorySet(elements ...v1.SearchCategory) FrozenV1SearchCategorySet {
	underlying := make(map[v1.SearchCategory]struct{}, len(elements))
	for _, elem := range elements {
		underlying[elem] = struct{}{}
	}
	return FrozenV1SearchCategorySet{
		underlying: underlying,
	}
}

// Contains returns whether the set contains the element.
func (k FrozenV1SearchCategorySet) Contains(elem v1.SearchCategory) bool {
	_, ok := k.underlying[elem]
	return ok
}

// Cardinality returns the cardinality of the set.
func (k FrozenV1SearchCategorySet) Cardinality() int {
	return len(k.underlying)
}

// AsSlice returns the elements of the set. The order is unspecified.
func (k FrozenV1SearchCategorySet) AsSlice() []v1.SearchCategory {
	if len(k.underlying) == 0 {
		return nil
	}
	slice := make([]v1.SearchCategory, 0, len(k.underlying))
	for elem := range k.underlying {
		slice = append(slice, elem)
	}
	return slice
}

// AsSortedSlice returns the elements of the set as a sorted slice.
func (k FrozenV1SearchCategorySet) AsSortedSlice(less func(i, j v1.SearchCategory) bool) []v1.SearchCategory {
	slice := k.AsSlice()
	if len(slice) < 2 {
		return slice
	}
	// Since we're generating the code, we might as well use sort.Sort
	// and avoid paying the reflection penalty of sort.Slice.
	sortable := &sortablev1SearchCategorySlice{slice: slice, less: less}
	sort.Sort(sortable)
	return sortable.slice
}
