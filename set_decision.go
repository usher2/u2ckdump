package main

// Uint64SearchIndex - decision map of array object for ref purpose.
type Uint64SearchIndex map[uint64]IntArrayStorage

// Remove - delete the decision.
func (a *Uint64SearchIndex) Remove(decision uint64, id int32) {
	if v, ok := (*a)[decision]; ok {
		v = v.Del(id)

		if len(v) == 0 {
			delete(*a, decision)

			return
		}

		(*a)[decision] = v
	}
}

// Insert - add the decision.
func (a *Uint64SearchIndex) Insert(decision uint64, id int32) {
	v, ok := (*a)[decision]
	if !ok {
		v = make(IntArrayStorage, 0, 1)
	}

	(*a)[decision] = v.Add(id)
}
