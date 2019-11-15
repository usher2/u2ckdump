package main

type Ip4Set map[uint32]IntSet

func (a *Ip4Set) DelIP(ip uint32, id int) {
	if v, ok := (*a)[ip]; ok {
		delete(v, id)
		if len(v) == 0 {
			delete(*a, ip)
		}
	}
}

func (a *Ip4Set) AddIP4(ip uint32, id int) {
	if v, ok := (*a)[ip]; !ok {
		v = make(IntSet)
		v[id] = NothingV
		(*a)[ip] = v
	} else {
		v[id] = NothingV
	}
}
