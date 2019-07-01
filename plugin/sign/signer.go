package sign

import (
	"os"
	"path/filepath"
	"time"

	"github.com/coredns/coredns/plugin/file/tree"
	clog "github.com/coredns/coredns/plugin/pkg/log"

	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin("sign")

// Signer holds the data need to sign a zone file.
type Signer struct {
	keys      []Pair
	origin    string
	dbfile    string
	directory string
	jitter    time.Duration

	signedfile string
	stop       chan struct{}

	expiration uint32
	inception  uint32
	ttl        uint32
}

// Sign signs a zone file according to the parameters in s.
func (s Signer) Sign(now time.Time) error {
	now = now.UTC()
	rd, err := os.Open(s.dbfile)
	if err != nil {
		return err
	}

	z, err := Parse(rd, s.origin, s.dbfile)
	if err != nil {
		return err
	}

	s.inception, s.expiration = lifetime(time.Now().UTC())

	s.ttl = z.Apex.SOA.Header().Ttl
	z.Apex.SOA.Serial = uint32(time.Now().Unix())
	names, apex := names(s.origin, z)
	ln := len(names)

	// TODO(miek): empty zone
	var nsec *dns.NSEC
	if apex {
		nsec = NSEC(s.origin, names[(ln+1)%ln], s.ttl, []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC})
		z.Insert(nsec)
	}

	for _, pair := range s.keys {
		z.Insert(pair.Public)
		z.Insert(pair.Public.ToDS(dns.SHA1))
		z.Insert(pair.Public.ToDS(dns.SHA256))
		z.Insert(pair.Public.ToCDNSKEY())
	}
	for _, pair := range s.keys {
		rrsig, err := pair.signRRs([]dns.RR{z.Apex.SOA}, s.origin, s.ttl, s.inception, s.expiration)
		if err != nil {
			return err
		}
		z.Insert(rrsig)
		rrsig, err = pair.signRRs(z.Apex.NS, s.origin, s.ttl, s.inception, s.expiration)
		if err != nil {
			return err
		}
		z.Insert(rrsig)
		if apex {
			rrsig, err = pair.signRRs([]dns.RR{nsec}, s.origin, s.ttl, s.inception, s.expiration)
			if err != nil {
				return err
			}
			z.Insert(rrsig)
		}
	}

	// We are walking the tree in the same direction, so names[] can be used here to indicated the next element.
	i := 1
	err = z.Walk(func(e *tree.Elem, zrrs map[uint16][]dns.RR) error {
		if !apex && e.Name() == s.origin {
			nsec := NSEC(e.Name(), names[(ln+i)%ln], s.ttl, append(e.Types(), dns.TypeNS, dns.TypeSOA, dns.TypeNSEC, dns.TypeRRSIG))
			z.Insert(nsec)
		} else {
			nsec := NSEC(e.Name(), names[(ln+i)%ln], s.ttl, append(e.Types(), dns.TypeNSEC, dns.TypeRRSIG))
			z.Insert(nsec)
		}

		for t, rrs := range zrrs {
			if t == dns.TypeRRSIG {
				continue
			}
			for _, pair := range s.keys {
				rrsig, err := pair.signRRs(rrs, s.origin, s.ttl, s.inception, s.expiration)
				if err != nil {
					return err
				}
				e.Insert(rrsig)
			}
		}
		i++
		return nil
	})
	if err != nil {
		return err
	}

	return s.write(z)
}

// resign checks if the signed zone exists, or needs resigning.
func (s Signer) resign() bool {
	signedfile := filepath.Join(s.directory, s.signedfile)
	rd, err := os.Open(signedfile)
	if err != nil && os.IsNotExist(err) {
		return true
	}

	now := time.Now()
	return resign(rd, now)
}

// refresh checks every val if some zones need to be resigned.
func (s Signer) refresh(val time.Duration) {
	tick := time.NewTicker(val)
	defer tick.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-tick.C:
			// we just resign in this case.
			go func() {
				// need not to stomp no each other, some fix is need in file plugin
				now := time.Now()
				err := s.Sign(now)
				// Keeps these logs in sync with the ones in sign.go.
				if err != nil {
					log.Warningf("Failed to sign %q with key tags %q in %s: %s", s.origin, keyTag(s.keys), time.Since(now), err)
				} else {
					log.Infof("Signed %q with key tags %q in %s, saved in %q", s.origin, keyTag(s.keys), time.Since(now), filepath.Join(s.directory, s.signedfile))
				}
			}()
		}
	}
}

func lifetime(now time.Time) (uint32, uint32) {
	incep := uint32(now.Add(-3 * time.Hour).Unix())      // -(2+1) hours, be sure to catch daylight saving time and such
	expir := uint32(now.Add(21 * 24 * time.Hour).Unix()) // sign for 21 days
	return incep, expir
}
