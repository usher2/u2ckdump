package main

// IP4Set - int map of int array object for ref purpose.
type IP4Set map[uint32]ArrayIntSet

// Drop - delete item from the int map of int array.
func (a *IP4Set) Drop(ip uint32, id int32) {
	if v, ok := (*a)[ip]; ok {
		v = v.Del(id)

		if len(v) == 0 {
			delete(*a, ip)

			return
		}

		(*a)[ip] = v
	}
}

// Insert - add item to the string map of int array.
func (a *IP4Set) Insert(ip uint32, id int32) {
	v, ok := (*a)[ip]
	if !ok {
		v = make(ArrayIntSet, 0, 1)
	}

	(*a)[ip] = v.Add(id)
}
