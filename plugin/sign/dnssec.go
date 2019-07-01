package sign

import (
	"strconv"

	"github.com/miekg/dns"
)

func (p Pair) signRRs(rrs []dns.RR, signerName string, ttl, incep, expir uint32) (*dns.RRSIG, error) {
	rrsig := &dns.RRSIG{
		Hdr:        dns.RR_Header{Rrtype: dns.TypeRRSIG, Ttl: ttl},
		Algorithm:  p.Public.Algorithm,
		SignerName: signerName,
		OrigTtl:    ttl,
		Inception:  incep,
		Expiration: expir,
	}

	e := rrsig.Sign(p.Private, rrs)
	return rrsig, e
}

// keyTag returns the key tags of the keys in ps as a formatted string
func keyTag(ps []Pair) string {
	if len(ps) == 0 {
		return ""
	}
	s := ""
	for _, p := range ps {
		s += strconv.Itoa(int(p.Public.KeyTag())) + ","
	}
	return s[:len(s)-1]
}
