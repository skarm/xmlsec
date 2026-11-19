package encoding

import (
	"unicode/utf8"

	enc "golang.org/x/text/encoding"
)

func newThaiEncoding(label string, iso885911 bool) enc.Encoding {
	const (
		nonBreakingSpace = 0xa0
		thaiOffset       = 0x0e00 - nonBreakingSpace
		firstThaiLetter  = 0xa1
		lastThaiMark     = 0xda
		thaiBaht         = 0xdf
		lastThaiSymbol   = 0xfb
	)

	var forward [singleByteCodePageEntries]rune
	for octet := range forward {
		switch {
		case octet < utf8.RuneSelf || iso885911 && octet <= nonBreakingSpace:
			forward[octet] = rune(octet)
		case octet >= firstThaiLetter && octet <= lastThaiMark || octet >= thaiBaht && octet <= lastThaiSymbol:
			forward[octet] = rune(octet + thaiOffset)
		default:
			forward[octet] = utf8.RuneError
		}
	}

	return newSingleByteEncoding(label, forward)
}
