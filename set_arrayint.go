package main

// ArrayIntSet - int array object for ref purpose.
type ArrayIntSet []int32

// Blank - is the array empty?
func (a ArrayIntSet) Blank() bool {
	return len(a) == 0
}

// Add - add item to the array.
func (a ArrayIntSet) Add(x int32) ArrayIntSet {
	for _, v := range a {
		if x == v {
			return a
		}
	}

	return append(a, x)
}

// Del - del item from the array.
func (a ArrayIntSet) Del(x int32) ArrayIntSet {
	for i, v := range a {
		if x == v {
			return append(a[:i], a[i+1:]...)
		}
	}

	return a
}
