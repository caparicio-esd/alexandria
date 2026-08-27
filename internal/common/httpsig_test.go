package common

import "testing"

func TestHTTPSigBuild(t *testing.T) {
	t.Parallel()

	var s HTTPSig
	if err := s.Build(); err != nil {
		t.Fatalf("Build() unexpected error: %v", err)
	}
}
