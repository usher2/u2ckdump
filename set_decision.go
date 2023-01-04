package main

// DecisionSet - decision map of array object for ref purpose.
type DecisionSet map[uint64]ArrayIntSet

// Delete - delete the decision.
func (a *DecisionSet) Delete(decision uint64, id int32) {
	if v, ok := (*a)[decision]; ok {
		v = v.Del(id)
		if len(v) == 0 {
			delete(*a, decision)

			return
		}
		(*a)[decision] = v
	}
}

// Add - add the decision.
func (a *DecisionSet) Add(decision uint64, id int32) {
	v, ok := (*a)[decision]
	if !ok {
		v = make(ArrayIntSet, 0, 1)
	}

	(*a)[decision] = v.Add(id)
}
