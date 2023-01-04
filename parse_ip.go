package main

// my parser without slices
func ip4str2int(s string) uint32 {
	var ip, n uint32 = 0, 0
	var r uint = 24

	for i := 0; i < len(s); i++ {
		switch {
		case '0' <= s[i] && s[i] <= '9':
			n = n*10 + uint32(s[i]-'0')

			if n > 0xFF {
				return 0xFFFFFFFF
			}
		case s[i] == '.':
			if r == 0 {
				return 0xFFFFFFFF
			}

			ip = ip + (n << r)
			r = r - 8
			n = 0
		default:
			return 0xFFFFFFFF
		}
	}

	if r != 0 {
		return 0xFFFFFFFF
	}

	ip = ip + n

	return ip
}
