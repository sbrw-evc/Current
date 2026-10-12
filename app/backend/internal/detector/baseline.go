package detector

import (
	"math"
	"slices"
)

// madScale turns the median absolute deviation into a standard deviation
// estimate for normally distributed data.
const madScale = 1.4826

// median of v (0 for an empty slice). v is not modified.
func median(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := slices.Clone(v)
	slices.Sort(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

// mad is the median absolute deviation from the median.
func mad(v []float64) float64 {
	m := median(v)
	d := make([]float64, len(v))
	for i, x := range v {
		d[i] = math.Abs(x - m)
	}
	return median(d)
}

// percentile returns the p-th percentile (0..100, nearest-rank) of v padded
// with zeros up to total samples (missing samples are periods without
// traffic). total < len(v) is treated as len(v).
func percentile(v []float64, total int, p float64) float64 {
	n := max(total, len(v))
	if n == 0 {
		return 0
	}
	s := make([]float64, n)
	copy(s[n-len(v):], v) // zeros first
	slices.Sort(s)
	rank := int(math.Ceil(p / 100 * float64(n)))
	rank = min(max(rank, 1), n)
	return s[rank-1]
}

// BaselineResult describes the comparison of an actual rate with a baseline.
type BaselineResult struct {
	Expected  float64 // median of the samples
	Sigma     float64 // 1.4826 × MAD
	Deviation float64 // (actual - expected) / sigma; ±Inf when sigma is 0
	Breach    bool
	Direction string // "up" or "down" when Breach
}

// anomaly compares actual with the samples: breach when it deviates in the
// configured direction by more than max(K × sigma, Ratio × expected), and
// the larger of actual and expected reaches MinVolume. With fewer than
// MinSamples samples, or only zero samples, nothing breaches.
func anomaly(actual float64, samples []float64, b Baseline) BaselineResult {
	r := BaselineResult{}
	if len(samples) == 0 || len(samples) < b.MinSamples {
		return r
	}
	r.Expected = median(samples)
	r.Sigma = madScale * mad(samples)
	diff := actual - r.Expected
	switch {
	case r.Sigma > 0:
		r.Deviation = diff / r.Sigma
	case diff > 0:
		r.Deviation = math.Inf(1)
	case diff < 0:
		r.Deviation = math.Inf(-1)
	}
	// No history for the group (new interface, network, service): no baseline.
	if r.Expected == 0 && r.Sigma == 0 {
		return r
	}
	if math.Max(actual, r.Expected) < b.MinVolume {
		return r
	}
	limit := math.Max(b.K*r.Sigma, b.Ratio*r.Expected)
	dir := b.Direction
	if dir == "" {
		dir = "up"
	}
	if (dir == "up" || dir == "both") && diff > limit {
		r.Breach, r.Direction = true, "up"
	}
	if (dir == "down" || dir == "both") && -diff > limit {
		r.Breach, r.Direction = true, "down"
	}
	return r
}

// drop: expected (median) ≥ minVolume and actual < ratio × expected.
func drop(actual float64, samples []float64, ratio, minVolume float64, minSamples int) (expected float64, breach bool) {
	if len(samples) == 0 || len(samples) < minSamples {
		return 0, false
	}
	expected = median(samples)
	return expected, expected > 0 && expected >= minVolume && actual < ratio*expected
}
