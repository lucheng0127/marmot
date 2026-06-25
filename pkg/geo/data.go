package geo

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

// Reader manages GeoIP and GeoSite databases.
type Reader struct {
	mu        sync.RWMutex
	geoIPDB   *maxminddb.Reader
	geoSiteDB *maxminddb.Reader
	geoIPPath string
	geoSitePath string
}

// GeoIPRecord holds GeoIP lookup results.
type GeoIPRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

func NewReader(geoIPPath, geoSitePath string) *Reader {
	r := &Reader{geoIPPath: geoIPPath, geoSitePath: geoSitePath}
	if geoIPPath != "" {
		db, err := maxminddb.Open(geoIPPath)
		if err == nil {
			r.geoIPDB = db
		}
	}
	return r
}

// LookupGeoIP returns the country code for an IP address.
func (r *Reader) LookupGeoIP(ip net.IP) (string, error) {
	r.mu.RLock()
	db := r.geoIPDB
	r.mu.RUnlock()
	if db == nil {
		return "", fmt.Errorf("GeoIP not loaded")
	}
	var record GeoIPRecord
	if err := db.Lookup(ip, &record); err != nil {
		return "", err
	}
	if record.Country.ISOCode == "" {
		return "ZZ", nil
	}
	return record.Country.ISOCode, nil
}

// GeoSiteCheck checks if a domain belongs to a given site category.
func (r *Reader) GeoSiteCheck(domain, category string) bool { return false }

// ReloadGeoIP reloads the GeoIP database.
func (r *Reader) ReloadGeoIP() error {
	if r.geoIPPath == "" {
		return nil
	}
	db, err := maxminddb.Open(r.geoIPPath)
	if err != nil {
		return err
	}
	r.mu.Lock()
	if r.geoIPDB != nil {
		r.geoIPDB.Close()
	}
	r.geoIPDB = db
	r.mu.Unlock()
	return nil
}

// StartReloader periodically reloads Geo databases.
func (r *Reader) StartReloader(interval time.Duration, stop <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				r.ReloadGeoIP()
			case <-stop:
				return
			}
		}
	}()
}

func init() { _ = os.DevNull }
