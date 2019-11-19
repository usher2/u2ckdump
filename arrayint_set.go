package main

type ArrayIntSet []int32

func (a ArrayIntSet) Blank() bool { return len(a) == 0 }

func (a ArrayIntSet) Add(v int32) ArrayIntSet {
	for i := range a {
		if a[i] == v {
			return a
		}
	}
	return append(a, v)
}

func (a ArrayIntSet) Del(v int32) ArrayIntSet {
	idx := -1
	for i := range a {
		if a[i] == v {
			idx = i
			break
		}
	}
	if idx == -1 {
		return a
	}
	return append(a[:idx], a[idx+1:]...)
}
