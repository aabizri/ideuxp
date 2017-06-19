package ssu

import (
	"testing"
)

func TestFlag_Coherence(t *testing.T) {
	// Test for every possible byte that the decomposition followed by a composition give the same flag value
	for i := byte(0); i <= 254; i++ {
		// Byte 0 & 1 are discarded, so we skip the values where they are set
		if i&1 != 0 || i&2 != 0 {
			continue
		}

		p, r, e := decomposeFlag(i)
		j := composeFlag(p, r, e)
		t.Logf("For input byte %d, we got output byte %d [Payload: %v | Rekey: %v | Extended: %v]", i, j, p, r, e)
		if i != j {
			t.Errorf("non-coherent result for input %d: output %d", i, j)
		}
	}
}
