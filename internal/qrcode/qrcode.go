package qrcode

import (
	"fmt"
	"strings"
)

// Pure-Go compact ISO/IEC 18004 QR Code Generator (Byte Mode, Error Correction Level L, Versions 1..6).
// Zero external dependencies; renders both SVG (for WebUI) and Unicode half-block ASCII (for terminal).

type versionSpec struct {
	version    int
	size       int
	totalWords int
	ecWords    int
	dataBytes  int
	alignPos   []int
}

var versions = []versionSpec{
	{1, 21, 26, 7, 17, nil},
	{2, 25, 44, 10, 32, []int{6, 18}},
	{3, 29, 70, 15, 53, []int{6, 22}},
	{4, 33, 100, 20, 78, []int{6, 26}},
	{5, 37, 134, 26, 106, []int{6, 30}},
	{6, 41, 172, 36, 134, []int{6, 34}},
}

// Encode encodes a string (up to 134 bytes) into a QR matrix where true = dark module.
func Encode(text string) ([][]bool, error) {
	raw := []byte(text)
	var spec versionSpec
	for _, v := range versions {
		if len(raw) <= v.dataBytes {
			spec = v
			break
		}
	}
	if spec.version == 0 {
		return nil, fmt.Errorf("text too long for compact QR (%d bytes)", len(raw))
	}

	dataWords := spec.totalWords - spec.ecWords
	codewords := buildDataCodewords(raw, dataWords)

	// Version 6 EC-L uses 2 blocks; Versions 1..5 EC-L use 1 block
	var finalBytes []byte
	if spec.version < 6 {
		ec := reedSolomonEncode(codewords, spec.ecWords)
		finalBytes = append(codewords, ec...)
	} else {
		halfData := dataWords / 2
		halfEC := spec.ecWords / 2
		b1 := codewords[:halfData]
		b2 := codewords[halfData:]
		ec1 := reedSolomonEncode(b1, halfEC)
		ec2 := reedSolomonEncode(b2, halfEC)
		for i := 0; i < halfData; i++ {
			finalBytes = append(finalBytes, b1[i], b2[i])
		}
		for i := 0; i < halfEC; i++ {
			finalBytes = append(finalBytes, ec1[i], ec2[i])
		}
	}

	n := spec.size
	modules := make([][]bool, n)
	reserved := make([][]bool, n)
	for i := range modules {
		modules[i] = make([]bool, n)
		reserved[i] = make([]bool, n)
	}

	placeFinder(modules, reserved, 0, 0)
	placeFinder(modules, reserved, 0, n-7)
	placeFinder(modules, reserved, n-7, 0)

	// Timing patterns
	for i := 8; i < n-8; i++ {
		val := i%2 == 0
		if !reserved[6][i] {
			modules[6][i] = val
			reserved[6][i] = true
		}
		if !reserved[i][6] {
			modules[i][6] = val
			reserved[i][6] = true
		}
	}

	// Alignment patterns
	if len(spec.alignPos) > 0 {
		for _, r := range spec.alignPos {
			for _, c := range spec.alignPos {
				if (r == 6 && c == 6) || (r == 6 && c == n-7) || (r == n-7 && c == 6) {
					continue
				}
				placeAlignment(modules, reserved, r, c)
			}
		}
	}

	// Reserve format info areas & dark module
	for i := 0; i < 9; i++ {
		if i < n {
			reserved[8][i] = true
			reserved[i][8] = true
		}
	}
	for i := 0; i < 8; i++ {
		reserved[8][n-1-i] = true
		reserved[n-1-i][8] = true
	}
	modules[n-8][8] = true
	reserved[n-8][8] = true

	// Place data bits in upward/downward 2-column zig-zag
	bitIdx := 0
	totalBits := len(finalBytes) * 8
	upward := true
	for col := n - 1; col >= 1; col -= 2 {
		if col == 6 {
			col-- // Skip vertical timing pattern column
		}
		for step := 0; step < n; step++ {
			row := step
			if upward {
				row = n - 1 - step
			}
			for dx := 0; dx < 2; dx++ {
				c := col - dx
				if !reserved[row][c] {
					var bit bool
					if bitIdx < totalBits {
						b := finalBytes[bitIdx/8]
						bit = ((b >> (7 - (bitIdx % 8))) & 1) == 1
						bitIdx++
					}
					// Apply Mask 0: (row + c) % 2 == 0
					if (row+c)%2 == 0 {
						bit = !bit
					}
					modules[row][c] = bit
				}
			}
		}
		upward = !upward
	}

	// Format information for EC Level L (01) + Mask 0 (000) -> precomputed BCH bits = 0x77C4
	const formatBits = 0x77C4
	placeFormatBits(modules, formatBits)

	return modules, nil
}

func buildDataCodewords(raw []byte, targetWords int) []byte {
	var bits []uint8
	appendBits := func(val int, count int) {
		for i := count - 1; i >= 0; i-- {
			bits = append(bits, uint8((val>>i)&1))
		}
	}
	// Byte mode indicator (0100) + 8-bit character count (for Version 1..9)
	appendBits(0b0100, 4)
	appendBits(len(raw), 8)
	for _, b := range raw {
		appendBits(int(b), 8)
	}
	// Terminator (up to 4 zero bits)
	maxBits := targetWords * 8
	for i := 0; i < 4 && len(bits) < maxBits; i++ {
		bits = append(bits, 0)
	}
	for len(bits)%8 != 0 {
		bits = append(bits, 0)
	}
	out := make([]byte, 0, targetWords)
	for i := 0; i < len(bits); i += 8 {
		var b byte
		for j := 0; j < 8; j++ {
			b = (b << 1) | bits[i+j]
		}
		out = append(out, b)
	}
	pad := []byte{0xEC, 0x11}
	for i := 0; len(out) < targetWords; i++ {
		out = append(out, pad[i%2])
	}
	return out
}

func placeFinder(m, res [][]bool, row, col int) {
	n := len(m)
	for dr := -1; dr <= 7; dr++ {
		for dc := -1; dc <= 7; dc++ {
			r, c := row+dr, col+dc
			if r < 0 || r >= n || c < 0 || c >= n {
				continue
			}
			inOuter := dr >= 0 && dr <= 6 && dc >= 0 && dc <= 6 && (dr == 0 || dr == 6 || dc == 0 || dc == 6)
			inInner := dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4
			m[r][c] = inOuter || inInner
			res[r][c] = true
		}
	}
}

func placeAlignment(m, res [][]bool, centerR, centerC int) {
	for dr := -2; dr <= 2; dr++ {
		for dc := -2; dc <= 2; dc++ {
			r, c := centerR+dr, centerC+dc
			dark := dr == -2 || dr == 2 || dc == -2 || dc == 2 || (dr == 0 && dc == 0)
			m[r][c] = dark
			res[r][c] = true
		}
	}
}

func placeFormatBits(m [][]bool, formatBits int) {
	n := len(m)
	// Around top-left finder
	coords1 := [][2]int{
		{8, 0}, {8, 1}, {8, 2}, {8, 3}, {8, 4}, {8, 5}, {8, 7}, {8, 8},
		{7, 8}, {5, 8}, {4, 8}, {3, 8}, {2, 8}, {1, 8}, {0, 8},
	}
	// Split across bottom-left and top-right
	coords2 := [][2]int{
		{n - 1, 8}, {n - 2, 8}, {n - 3, 8}, {n - 4, 8}, {n - 5, 8}, {n - 6, 8}, {n - 7, 8},
		{8, n - 8}, {8, n - 7}, {8, n - 6}, {8, n - 5}, {8, n - 4}, {8, n - 3}, {8, n - 2}, {8, n - 1},
	}
	for i := 0; i < 15; i++ {
		bit := ((formatBits >> (14 - i)) & 1) == 1
		m[coords1[i][0]][coords1[i][1]] = bit
		m[coords2[i][0]][coords2[i][1]] = bit
	}
}

// GF(256) Reed-Solomon Error Correction with primitive polynomial 0x11D
var gfExp [512]byte
var gfLog [256]byte

func init() {
	x := 1
	for i := 0; i < 255; i++ {
		gfExp[i] = byte(x)
		gfLog[x] = byte(i)
		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x11D
		}
	}
	for i := 255; i < 512; i++ {
		gfExp[i] = gfExp[i-255]
	}
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

func reedSolomonEncode(data []byte, ecLen int) []byte {
	gen := []byte{1}
	for i := 0; i < ecLen; i++ {
		next := make([]byte, len(gen)+1)
		factor := gfExp[i]
		for j, g := range gen {
			next[j] ^= g
			next[j+1] ^= gfMul(g, factor)
		}
		gen = next
	}

	rem := make([]byte, ecLen)
	for _, b := range data {
		lead := b ^ rem[0]
		copy(rem, rem[1:])
		rem[ecLen-1] = 0
		if lead != 0 {
			for j := 0; j < ecLen; j++ {
				rem[j] ^= gfMul(gen[j+1], lead)
			}
		}
	}
	return rem
}

// RenderSVG renders a QR code for text as a crisp scalable SVG string.
func RenderSVG(text string) (string, error) {
	matrix, err := Encode(text)
	if err != nil {
		return "", err
	}
	n := len(matrix)
	quiet := 2
	total := n + quiet*2

	var sb strings.Builder
	fmt.Fprintf(&sb, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges" width="220" height="220">`, total, total)
	fmt.Fprintf(&sb, `<rect width="%d" height="%d" fill="#ffffff"/>`, total, total)
	sb.WriteString(`<path fill="#0f172a" d="`)
	for r := 0; r < n; r++ {
		for c := 0; c < n; c++ {
			if matrix[r][c] {
				fmt.Fprintf(&sb, "M%d,%dh1v1h-1z", c+quiet, r+quiet)
			}
		}
	}
	sb.WriteString(`"/></svg>`)
	return sb.String(), nil
}

// RenderTerminal renders a compact terminal QR code using Unicode half-blocks.
func RenderTerminal(text string) (string, error) {
	matrix, err := Encode(text)
	if err != nil {
		return "", err
	}
	n := len(matrix)
	quiet := 2
	total := n + quiet*2

	isDark := func(r, c int) bool {
		mr, mc := r-quiet, c-quiet
		if mr < 0 || mr >= n || mc < 0 || mc >= n {
			return false
		}
		return matrix[mr][mc]
	}

	var sb strings.Builder
	for r := 0; r < total; r += 2 {
		sb.WriteString("  ")
		for c := 0; c < total; c++ {
			top := isDark(r, c)
			bot := false
			if r+1 < total {
				bot = isDark(r+1, c)
			}
			switch {
			case top && bot:
				sb.WriteString(" ")
			case top && !bot:
				sb.WriteString("▄")
			case !top && bot:
				sb.WriteString("▀")
			default:
				sb.WriteString("█")
			}
		}
		sb.WriteString("\n")
	}
	return sb.String(), nil
}
