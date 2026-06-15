package geoip

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/oschwald/maxminddb-golang"
)

// MaxMindResolver is a Resolver backed by a MaxMind GeoLite2-City mmdb
// file. The reader is loaded once at construction; we hold it open for
// the lifetime of the process because Lookup is on the hot audit path.
//
// Use NewMaxMindResolver from the operator-supplied path; the resolver
// is safe for concurrent use.
type MaxMindResolver struct {
	mu     sync.RWMutex
	reader *maxminddb.Reader
	path   string
}

// NewMaxMindResolver opens the mmdb at path. Returns an error if the
// file is missing or malformed — operators MUST decide whether that
// fails startup or downgrades to NoopResolver; this package does not
// choose for them.
func NewMaxMindResolver(path string) (*MaxMindResolver, error) {
	if path == "" {
		return nil, errors.New("geoip: empty mmdb path")
	}
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("geoip: stat %s: %w", path, err)
	}
	r, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("geoip: open %s: %w", path, err)
	}
	return &MaxMindResolver{reader: r, path: path}, nil
}

// Lookup resolves the IP. Returns an empty Location for malformed IPs
// and for addresses the database has no row for.
func (m *MaxMindResolver) Lookup(raw string) (Location, error) {
	ip := net.ParseIP(raw)
	if ip == nil {
		return Location{}, nil
	}
	var rec mmdbCityRecord
	m.mu.RLock()
	err := m.reader.Lookup(ip, &rec)
	m.mu.RUnlock()
	if err != nil {
		return Location{}, fmt.Errorf("geoip: lookup: %w", err)
	}
	return Location{
		Country: rec.Country.IsoCode,
		Region:  firstSubdivisionName(rec.Subdivisions),
		City:    rec.City.Names["en"],
	}, nil
}

// Close releases the underlying mmdb reader. Safe to call multiple
// times. Should be wired into the bootstrap cleanup hook.
func (m *MaxMindResolver) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.reader == nil {
		return nil
	}
	err := m.reader.Close()
	m.reader = nil
	return err
}

type mmdbCityRecord struct {
	Country struct {
		IsoCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Subdivisions []struct {
		IsoCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
}

func firstSubdivisionName(subs []struct {
	IsoCode string            `maxminddb:"iso_code"`
	Names   map[string]string `maxminddb:"names"`
}) string {
	if len(subs) == 0 {
		return ""
	}
	if n := subs[0].Names["en"]; n != "" {
		return n
	}
	return subs[0].IsoCode
}
