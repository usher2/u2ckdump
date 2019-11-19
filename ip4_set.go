package main

type Ip4Set map[uint32]ArrayIntSet

func (a *Ip4Set) Delete(ip uint32, id int32) {
	if v, ok := (*a)[ip]; ok {
		v = v.Del(id)
		if len(v) == 0 {
			delete(*a, ip)
		} else {
			(*a)[ip] = v
		}
	}
}

func (a *Ip4Set) Add(ip uint32, id int32) {
	if v, ok := (*a)[ip]; !ok {
		v = make(ArrayIntSet, 0, 1)
		(*a)[ip] = v.Add(id)
	} else {
		(*a)[ip] = v.Add(id)
	}
}
