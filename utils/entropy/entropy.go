// entropy is a package for computing entropy of binary streams.
package entropy

import (
	"math"
)

// Entropy is an object that computes the entropy of a stream
// of bytes. It satisfies the `io.Writer` interface, so call
// the `.Write()` method to populate the statistical distribution.
// Then call `.GetEntropy()` to fetch the computed entropy value.
// Use a new instance of this object for each stream of data, as
// it does not reset.
type Entropy struct {
	count   [256]uint64
	dataLen uint64
}

// New is the constructor for Entropy instances.
func New() (*Entropy, error) {
	return &Entropy{}, nil
}

// Write processes the bytes and updates the statistical
// distribution for entropy calculations.
func (e *Entropy) Write(p []byte) (int, error) {
	for _, b := range p {
		e.count[b] += 1
	}
	e.dataLen += uint64(len(p))
	return len(p), nil
}

// GetEntropy computes the entropy of the processed bytes
// from the statistical distribution captured during `.Write()`.
func (e *Entropy) GetEntropy() (float64, error) {
	var entropy float64
	dataLen := float64(e.dataLen)
	for _, count := range e.count {
		p_x := float64(count) / dataLen
		if p_x > 0 {
			entropy += -p_x * math.Log2(p_x)
		}
	}
	return entropy, nil
}
