package main

// IPv4StrToInt converts a string containing an IPv4 address to its uint32 representation.
// The input string should be in the format "xxx.xxx.xxx.xxx" where xxx is a number between 0 and 255.
// If the input string is not a valid IPv4 address, the function returns 0xFFFFFFFF.
func IPv4StrToInt(s string) uint32 {
	var ip, n uint32
	var r uint = 24       // r tracks the remaining bits to shift the next octet.
	var dotCount byte = 1 // dotCount tracks the number of consecutive dots.

	// Iterate through the input string
	for i := 0; i < len(s); i++ {
		switch {
		case '0' <= s[i] && s[i] <= '9': // Check if the current character is a digit.
			n = n*10 + uint32(s[i]-'0') // Update n with the current digit.

			// Check if the current octet value exceeds the maximum allowed value (255).
			if n > 0xFF {
				return 0xFFFFFFFF
			}

			dotCount = 0 // Reset the dot count.
		case s[i] == '.': // Check if the current character is a dot.
			// If no more octets are expected or it's a second consecutive dot, return an error.
			if r == 0 || dotCount > 0 {
				return 0xFFFFFFFF
			}

			// Combine the current octet value with the existing IP representation.
			ip |= n << r
			r -= 8     // Update the remaining bits for the next octet.
			n = 0      // Reset n for the next octet.
			dotCount++ // Increment the dot count.
		default: // If the current character is neither a digit nor a dot, return an error.
			return 0xFFFFFFFF
		}
	}

	// If the address is incomplete, return an error.
	if r != 0 || dotCount > 0 {
		return 0xFFFFFFFF
	}

	// Combine the last octet value with the existing IP representation.
	ip |= n

	return ip
}
