package main

// StringMap - string existing map.
type StringMap map[string]Nothing

// NewStringSet - StringSet constructor.
func NewStringSet(size int) StringMap {
	return make(StringMap, size)
}

// StringSearchIndex - string map of int array object for ref purpose.
type StringSearchIndex map[string]IntArrayStorage

// Remove - delete item from the string map of int array.
func (a *StringSearchIndex) Remove(s string, id int32) bool {
	if v, ok := (*a)[s]; ok {
		v = v.Del(id)

		if len(v) == 0 {
			delete(*a, s)

			return true
		}

		(*a)[s] = v
	}

	return false
}

// Insert - add item to the string map of int array.
func (a *StringSearchIndex) Insert(s string, id int32) bool {
	first := false

	v, ok := (*a)[s]
	if !ok {
		v = make(IntArrayStorage, 0, 1)
		first = true
	}

	(*a)[s] = v.Add(id)

	return first
}
