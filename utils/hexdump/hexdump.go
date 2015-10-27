package hexdump

import (
	"fmt"
	"io"
	"strings"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func isPrintable(a byte) bool {
	return a >= 32 && a <= 126
}

func min(a uint64, b uint64) uint64 {
	if a < b {
		return a
	} else {
		return b
	}
}

type Hexdump struct {
	rowLength uint64
}

/**
Creat a new Hexdumper with `rowLength` bytes dumped per row.
*/
func New(rowLength uint) (*Hexdump, error) {
	return &Hexdump{
		rowLength: 0x10,
	}, nil
}

func (h Hexdump) makeLine(data []byte) ([]string, []string, error) {
	hexChars := make([]string, h.rowLength)
	asciiChars := make([]string, h.rowLength)

	for j := uint64(0); j < h.rowLength; j++ {
		if j < uint64(len(data)) {
			c := data[j]
			hexChars[j] = fmt.Sprintf("%02X", c)
			if isPrintable(c) {
				asciiChars[j] = fmt.Sprintf("%s", string(c))
			} else {
				asciiChars[j] = "."
			}
		} else {
			hexChars[j] = "  "
			asciiChars[j] = " "
		}
	}

	return hexChars, asciiChars, nil
}

/**
Write a hex dump to `w` from the offset `offset`.
*/
func (h Hexdump) DumpFromOffset(data []byte, offset uint64, w io.Writer) error {
	numRows := uint64(len(data)) / h.rowLength
	if uint64(len(data))%h.rowLength != 0 {
		numRows += 1
	}
	for i := uint64(0); i < numRows; i++ {
		slice := data[uint64(i)*h.rowLength : min(uint64(i+1)*h.rowLength, uint64(len(data)))]
		hexChars, asciiChars, e := h.makeLine(slice)
		check(e)

		w.Write([]byte(fmt.Sprintf("%06X: ", offset+i*h.rowLength)))
		w.Write([]byte(fmt.Sprintf("%s", strings.Join(hexChars, " "))))
		w.Write([]byte(fmt.Sprintf("  ")))
		w.Write([]byte(fmt.Sprintf("%s", strings.Join(asciiChars, ""))))
		w.Write([]byte(fmt.Sprintf("\n")))
	}
	return nil
}

/**
Write a hex dump to `w` from the offset 0.
*/
func (h Hexdump) Dump(data []byte, w io.Writer) error {
	return h.DumpFromOffset(data, 0, w)
}

/**
Static function to write a hex dump to `w` from the offset `offset`.
Writes 0x10 dumped bytes per line.
*/
func DumpFromOffset(data []byte, offset uint64, w io.Writer) error {
	h, e := New(0x10)
	if e != nil {
		return e
	}
	return h.DumpFromOffset(data, offset, w)
}

/**
Static function to write a hex dump to `w` from the offset 0.
Writes 0x10 dumped bytes per line.
*/
func Dump(data []byte, w io.Writer) error {
	return DumpFromOffset(data, 0, w)
}
