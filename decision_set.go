package main

type DecisionSet map[uint64]ArrayIntSet

func (a *DecisionSet) Delete(decision uint64, id int32) {
	if v, ok := (*a)[decision]; ok {
		v = v.Del(id)
		if len(v) == 0 {
			delete(*a, decision)
		} else {
			(*a)[decision] = v
		}
	}
}

func (a *DecisionSet) Add(decision uint64, id int32) {
	if v, ok := (*a)[decision]; !ok {
		v = make(ArrayIntSet, 0, 1)
		(*a)[decision] = v.Add(id)
	} else {
		(*a)[decision] = v.Add(id)
	}
}
