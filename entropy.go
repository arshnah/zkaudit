package zkaudit

import "math"

const highEntropyThreshold = 4.5

func shannonEntropy(s string) float64 {
	data := []byte(s)
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	total := float64(len(data))
	entropy := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func looksHighEntropy(s string) bool {
	if len(s) < 24 {
		return false
	}
	return shannonEntropy(s) >= highEntropyThreshold
}
