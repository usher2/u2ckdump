package main

type StringSet map[string]Nothing

func NewStringSet(size int) StringSet {
	return make(StringSet, size)
}

type StringIntSet map[string]ArrayIntSet

func (a *StringIntSet) Delete(i string, id int32) (last bool) {
	last = false
	if v, ok := (*a)[i]; ok {
		v = v.Del(id)
		if len(v) == 0 {
			delete(*a, i)
			last = true
		} else {
			(*a)[i] = v
		}
	}
	return
}

func (a *StringIntSet) Add(i string, id int32) (first bool) {
	first = false
	if v, ok := (*a)[i]; !ok {
		v = make(ArrayIntSet, 0, 1)
		(*a)[i] = v.Add(id)
		first = true
	} else {
		(*a)[i] = v.Add(id)
	}
	return
}
