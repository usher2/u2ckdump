package main

type StringSet map[string]Nothing

func NewStringSet(size int) StringSet {
	return make(StringSet, size)
}

type StringIntSet map[string]IntSet

func (a *StringIntSet) Delete(i string, id int32) {
	if v, ok := (*a)[i]; ok {
		delete(v, id)
		if len(v) == 0 {
			delete(*a, i)
		}
	}
}

func (a *StringIntSet) Add(i string, id int32) {
	if v, ok := (*a)[i]; !ok {
		v = make(IntSet)
		v[id] = NothingV
		(*a)[i] = v
	} else {
		v[id] = NothingV
	}
}
