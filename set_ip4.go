package main

// Uint32SearchIndex - int map of int array object for ref purpose.
type Uint32SearchIndex map[uint32]IntArrayStorage

// Remove - delete item from the int map of int array.
func (a *Uint32SearchIndex) Remove(ip uint32, id int32) {
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
func (a *Uint32SearchIndex) Insert(ip uint32, id int32) {
	v, ok := (*a)[ip]
	if !ok {
		v = make(IntArrayStorage, 0, 1)
	}

	(*a)[ip] = v.Add(id)
}
