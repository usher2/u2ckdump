package main

type StringSet map[string]Nothing

func NewStringSet(size int) StringSet {
	return make(StringSet, size)
}

type StringIntSet map[string]IntSet

func (a *StringIntSet) Delete(i string, id int32) (last bool) {
	last = false
	if v, ok := (*a)[i]; ok {
		delete(v, id)
		if len(v) == 0 {
			delete(*a, i)
			last = true
		}
	}
	return
}

func (a *StringIntSet) Add(i string, id int32) (first bool) {
	first = false
	if v, ok := (*a)[i]; !ok {
		first = true
		v = make(IntSet)
		v[id] = NothingV
		(*a)[i] = v
	} else {
		v[id] = NothingV
	}
	return
}
