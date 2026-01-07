// Package cache provides functionality to save and load optimized IP results
// for reuse across multiple scanning sessions.
package cache

import (
	"encoding/json"
	"net/netip"
	"os"
	"sort"
	"time"
)

// CachedIP represents a cached IP with its performance metrics.
type CachedIP struct {
	IP           netip.Addr `json:"ip"`
	ScoreMS      float64    `json:"score_ms"`
	DownloadMbps float64    `json:"download_mbps"`
	DownloadOK   bool       `json:"download_ok"`
	Colo         string     `json:"colo,omitempty"`
	LastTested   time.Time  `json:"last_tested"`
	TestCount    int        `json:"test_count"`
}

// Cache holds the cached IP results.
type Cache struct {
	Version   int        `json:"version"`
	UpdatedAt time.Time  `json:"updated_at"`
	IPs       []CachedIP `json:"ips"`
}

const (
	// CurrentVersion is the current cache format version.
	CurrentVersion = 1
	// DefaultCacheFile is the default cache file path.
	DefaultCacheFile = ".mcis_cache.json"
)

// Load loads the cache from a file. Returns an empty cache if file doesn't exist.
func Load(path string) (*Cache, error) {
	if path == "" {
		path = DefaultCacheFile
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Cache{
				Version:   CurrentVersion,
				UpdatedAt: time.Now(),
				IPs:       []CachedIP{},
			}, nil
		}
		return nil, err
	}

	var cache Cache
	if err := json.Unmarshal(data, &cache); err != nil {
		// Return empty cache if file is corrupted
		return &Cache{
			Version:   CurrentVersion,
			UpdatedAt: time.Now(),
			IPs:       []CachedIP{},
		}, nil
	}

	return &cache, nil
}

// Save saves the cache to a file.
func (c *Cache) Save(path string) error {
	if path == "" {
		path = DefaultCacheFile
	}

	c.UpdatedAt = time.Now()
	c.Version = CurrentVersion

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// GetIPs returns the list of cached IPs.
func (c *Cache) GetIPs() []netip.Addr {
	ips := make([]netip.Addr, len(c.IPs))
	for i, ip := range c.IPs {
		ips[i] = ip.IP
	}
	return ips
}

// Update updates the cache with new results.
// It merges the new results with existing cache, keeping the best performers.
// maxCount specifies the maximum number of IPs to keep in cache.
func (c *Cache) Update(newIPs []CachedIP, maxCount int) {
	if maxCount <= 0 {
		maxCount = 10
	}

	// Create a map for quick lookup
	ipMap := make(map[netip.Addr]*CachedIP)

	// Add existing IPs to map
	for i := range c.IPs {
		ip := c.IPs[i]
		ipMap[ip.IP] = &ip
	}

	// Update with new IPs
	for _, newIP := range newIPs {
		existing, exists := ipMap[newIP.IP]
		if exists {
			// Update existing entry with better score
			existing.TestCount++
			// Keep the better score (lower is better for latency)
			if newIP.DownloadOK && (!existing.DownloadOK || newIP.DownloadMbps > existing.DownloadMbps) {
				existing.ScoreMS = newIP.ScoreMS
				existing.DownloadMbps = newIP.DownloadMbps
				existing.DownloadOK = newIP.DownloadOK
			} else if newIP.ScoreMS < existing.ScoreMS {
				existing.ScoreMS = newIP.ScoreMS
			}
			existing.LastTested = newIP.LastTested
			if newIP.Colo != "" {
				existing.Colo = newIP.Colo
			}
		} else {
			// Add new IP
			newEntry := newIP
			newEntry.TestCount = 1
			ipMap[newIP.IP] = &newEntry
		}
	}

	// Convert map back to slice
	result := make([]CachedIP, 0, len(ipMap))
	for _, ip := range ipMap {
		result = append(result, *ip)
	}

	// Sort by download speed (descending) for IPs with download test,
	// then by score (ascending) for others
	sort.Slice(result, func(i, j int) bool {
		// Both have download results - compare by download speed
		if result[i].DownloadOK && result[j].DownloadOK {
			return result[i].DownloadMbps > result[j].DownloadMbps
		}
		// One has download result - prioritize it
		if result[i].DownloadOK {
			return true
		}
		if result[j].DownloadOK {
			return false
		}
		// Neither has download result - compare by score
		return result[i].ScoreMS < result[j].ScoreMS
	})

	// Keep only top maxCount IPs
	if len(result) > maxCount {
		result = result[:maxCount]
	}

	c.IPs = result
}

// Clear clears the cache.
func (c *Cache) Clear() {
	c.IPs = []CachedIP{}
}

// IsEmpty returns true if the cache has no IPs.
func (c *Cache) IsEmpty() bool {
	return len(c.IPs) == 0
}

// Len returns the number of cached IPs.
func (c *Cache) Len() int {
	return len(c.IPs)
}
