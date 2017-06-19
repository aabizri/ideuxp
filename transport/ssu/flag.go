package ssu

/*
   Bit order: 76543210 (bit 7 is MSB)

   bits 7-4: payload type, as a 4-bit integer
      bit 3: If 1, rekey data is included. Always 0, unimplemented
      bit 2: If 1, extended options are included. Always 0 before release
             0.9.24.
   bits 1-0: reserved, set to 0 for compatibility with future uses
*/
func decomposeFlag(flag byte) (payload byte, rekey bool, extended bool) {
	// Bit 2
	if flag&4 != 0 {
		extended = true
	}

	// Bit 3
	if flag&8 != 0 {
		rekey = true
	}

	// Bit 4, 5, 6, 7 indicate the payload type, in MSB
	for i := byte(16); i <= 128 && i >= 16; i *= 2 {
		if flag&i != 0 {
			payload += i / 16
		}
	}

	// Return
	return
}

func composeFlag(payload byte, rekey bool, extended bool) byte {
	var flag byte

	// Bit 2
	if extended {
		flag += 4
	}

	// Bit 3
	if rekey {
		flag += 8
	}

	// Bit 4-7
	for i := byte(1); i <= 8; i *= 2 {
		if payload&i != 0 {
			flag += i * 16
		}
	}

	// Return
	return flag
}
