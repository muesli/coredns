package sign

import (
	"testing"
	"time"

	"github.com/caddyserver/caddy"
)

func TestSign(t *testing.T) {
	input := `sign testdata/db.miek.nl miek.nl {
		key file testdata/Kmiek.nl.+013+59725
		directory testdata
	}`
	c := caddy.NewTestController("dns", input)
	sign, err := parse(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(sign.signers) != 1 {
		t.Fatalf("Expected 1 signer got %d", len(sign.signers))
	}
	//defer os.Remove("db.miek.nl.signed")
	if err := sign.signers[0].Sign(time.Now()); err != nil {
		t.Error(err)
	}
}
