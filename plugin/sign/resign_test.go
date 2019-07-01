package sign

import (
	"strings"
	"testing"
	"time"
)

func TestResign(t *testing.T) {
	zr := strings.NewReader(`miek.nl.	1800	IN	RRSIG	SOA 13 2 1800 20190808191936 20190718161936 59725 miek.nl. eU6gI1OkSEbyt`)

	// resign adds 14 days to it, this should not expire this RRSIG.
	then := time.Date(2019, 7, 18, 22, 50, 0, 0, time.UTC)
	if x := resign(zr, then); x {
		t.Errorf("Expected RRSIG to be valid for %s, got invalid", then.Add(14*24*time.Hour))
	}

	zr = strings.NewReader(`miek.nl.	1800	IN	RRSIG	SOA 13 2 1800 20190808191936 20190718161936 59725 miek.nl. eU6gI1OkSEbyt`)
	then = time.Date(2019, 8, 1, 22, 50, 0, 0, time.UTC)
	if x := resign(zr, then); !x {
		t.Errorf("Expected RRSIG to be invalid for %s, got valid", then.Add(14*24*time.Hour))
	}
}
