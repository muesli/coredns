// Package sign implements a zone signer as a CoreDNS plugin.
package sign

import (
	"path/filepath"
	"time"
)

// Sign holders signers that sign the various zones files.
type Sign struct {
	signers []Signer
}

// OnStartup scans all signers and signs are resigns zones if needed.
func (s *Sign) OnStartup() error {
	for _, signer := range s.signers {
		resign := signer.resign()

		if !resign {
			continue
		}

		go func() {
			// need not to stomp no each other, same fix is need in file plugin
			now := time.Now()
			err := signer.Sign(now)
			if err != nil {
				log.Warningf("Failed to sign %q with key tags %q in %s: %s", signer.origin, keyTag(signer.keys), time.Since(now), err)
			} else {
				log.Infof("Signed %q with key tags %q in %s, saved in %q", signer.origin, keyTag(signer.keys), time.Since(now), filepath.Join(signer.directory, signer.signedfile))
			}
		}()
	}
	return nil
}
