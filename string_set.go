package main

type StringSet map[string]IntSet

func (a *StringSet) Delete(i string, id int) {
	if v, ok := (*a)[i]; ok {
		delete(v, id)
		if len(v) == 0 {
			delete(*a, i)
		}
	}
}

func (a *StringSet) Add(i string, id int) {
	if v, ok := (*a)[i]; !ok {
		v = make(IntSet)
		v[id] = NothingV
		(*a)[i] = v
	} else {
		v[id] = NothingV
	}
}
