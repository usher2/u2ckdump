package main

// IntArrayStorage - int array object for ref purpose.
type IntArrayStorage []int32

// Blank - is the array empty?
func (a IntArrayStorage) Blank() bool {
	return len(a) == 0
}

// Add - add item to the array.
func (a IntArrayStorage) Add(x int32) IntArrayStorage {
	for _, v := range a {
		if x == v {
			return a
		}
	}

	return append(a, x)
}

// Del - del item from the array.
func (a IntArrayStorage) Del(x int32) IntArrayStorage {
	for i, v := range a {
		if x == v {
			return append(a[:i], a[i+1:]...)
		}
	}

	return a
}
