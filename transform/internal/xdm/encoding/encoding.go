// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

// Package encoding resolves encoding labels to internal codecs and provides
// strict XML byte-decoding helpers. Codec availability is separate from the
// encodings permitted by an input profile; callers must enforce that policy.
package encoding

import (
	"strings"
	"unicode/utf8"

	"github.com/skarm/xmlsec/internal/lexicon"

	enc "golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/encoding/korean"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/encoding/traditionalchinese"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/encoding/unicode/utf32"
)

// Load returns a codec for a recognized normalized encoding name, or nil when
// unsupported. Codec availability does not authorize an encoding in an XML input
// profile.
func Load(name string) enc.Encoding {
	norm := normalizeEncodingName(name)
	if ok := asciiEncodingNames(norm); ok {
		return asciiEncoding{}
	}

	for _, load := range [...]func(string) enc.Encoding{loadUnicodeEncoding, loadEastAsianEncoding, loadISOEncoding, loadLegacyEncoding} {
		if codec := load(norm); codec != nil {
			return codec
		}
	}

	return nil
}

// IsASCII recognizes the same strict US-ASCII aliases as Load.
func IsASCII(name string) bool {
	return asciiEncodingNames(normalizeEncodingName(name))
}

// Repertoire returns a character probe using a dedicated encoder. The closure
// reuses its buffers and must not be shared across concurrent serializations.
func Repertoire(encoder *enc.Encoder) func(rune) bool {
	// Scratch capacity is in bytes; the probe supplies one complete scalar.
	const (
		repertoireBufferBytes = 64
		completeScalarInput   = true
	)

	var (
		source      [utf8.UTFMax]byte
		destination [repertoireBufferBytes]byte
	)

	return func(r rune) bool {
		n := utf8.EncodeRune(source[:], r)

		encoder.Reset()
		_, consumed, err := encoder.Transform(destination[:], source[:n], completeScalarInput)

		return err == nil && consumed == n
	}
}

func normalizeEncodingName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.ToLower(name)

	return strings.Map(func(r rune) rune {
		switch r {
		case '-', '_', ':', '.', ' ':
			return -1
		}

		return r
	}, name)
}

// asciiEncodingNames is the set of normalized names (see normalizeEncodingName)
// that denote US-ASCII, covering every IANA-registered alias plus the common
// "ascii" synonym. It is the single source of truth for both Load (which returns
// the strict US-ASCII codec) and IsASCII.
func asciiEncodingNames(key string) bool {
	// These normalized aliases preserve the exact recognized codec vocabulary.
	const (
		aliasUSASCII       = "usascii"
		aliasASCII         = "ascii"
		aliasANSIX341968   = "ansix341968"
		aliasANSIX341986   = "ansix341986"
		aliasCSASCII       = "csascii"
		aliasISOIR6        = "isoir6"
		aliasISO646US      = "iso646us"
		aliasISO646IRV1991 = "iso646irv1991"
		aliasUS            = "us"
		aliasIBM367        = "ibm367"
		aliasCP367         = "cp367"
	)

	switch key {
	case aliasUSASCII, aliasASCII, aliasANSIX341968, aliasANSIX341986, aliasCSASCII, aliasISOIR6, aliasISO646US, aliasISO646IRV1991, aliasUS, aliasIBM367, aliasCP367:
		return true
	}

	return false
}

func loadUnicodeEncoding(norm string) enc.Encoding {
	// These normalized aliases preserve the exact recognized codec vocabulary.
	const (
		aliasUNICODE11UTF8  = "unicode11utf8"
		aliasUNICODE20UTF8  = "unicode20utf8"
		aliasXUNICODE20UTF8 = "xunicode20utf8"
		aliasUTF16LE        = "utf16le"
		aliasUNICODEFEFF    = "unicodefeff"
		aliasUTF16BE        = "utf16be"
		aliasUNICODEFFFE    = "unicodefffe"
		aliasUTF16          = "utf16"
		aliasUNICODE        = "unicode"
		aliasCSUNICODE      = "csunicode"
		aliasUCS4BE         = "ucs4be"
		aliasUTF32BE        = "utf32be"
		aliasISO10646UCS4   = "iso10646ucs4"
		aliasUCS4LE         = "ucs4le"
		aliasUTF32LE        = "utf32le"
		aliasUCS4           = "ucs4"
		aliasUTF32          = "utf32"
		aliasUCS42143       = "ucs42143"
		aliasUCS43412       = "ucs43412"
		aliasUCS2           = "ucs2"
		aliasISO10646UCS2   = "iso10646ucs2"
	)

	switch norm {
	case lexicon.EncodingUTF8Alt, aliasUNICODE11UTF8, aliasUNICODE20UTF8, aliasXUNICODE20UTF8:
		return unicode.UTF8
	case aliasUTF16LE, aliasUNICODEFEFF:
		return withStrictDecode(unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM), utf16CodeUnitBytes, orderLE2, ignoreLeadingBOM)
	case aliasUTF16BE, aliasUNICODEFFFE:
		return withStrictDecode(unicode.UTF16(unicode.BigEndian, unicode.IgnoreBOM), utf16CodeUnitBytes, orderBE2, ignoreLeadingBOM)
	case aliasUTF16, aliasUNICODE, aliasCSUNICODE:
		// UseBOM with LittleEndian default: x/text's decoder falls back to the
		// configured default (LE) when no BOM is present, so the validator's
		// no-BOM order must be LE to match.
		return withStrictDecode(unicode.UTF16(unicode.LittleEndian, unicode.UseBOM), utf16CodeUnitBytes, orderLE2, honorLeadingBOM)
	case aliasUCS4BE, aliasUTF32BE, aliasISO10646UCS4:
		return withStrictDecode(utf32.UTF32(utf32.BigEndian, utf32.IgnoreBOM), utf32CodeUnitBytes, orderBE4, ignoreLeadingBOM)
	case aliasUCS4LE, aliasUTF32LE:
		return withStrictDecode(utf32.UTF32(utf32.LittleEndian, utf32.IgnoreBOM), utf32CodeUnitBytes, orderLE4, ignoreLeadingBOM)
	case aliasUCS4, aliasUTF32:
		// UseBOM with BigEndian default: x/text's decoder falls back to the
		// configured default (BE) when no BOM is present, so the validator's
		// no-BOM order must be BE to match.
		return withStrictDecode(utf32.UTF32(utf32.BigEndian, utf32.UseBOM), utf32CodeUnitBytes, orderBE4, honorLeadingBOM)
	case aliasUCS42143:
		return withStrictDecode(&ucs4SwapEncoding{swap: swap2143}, utf32CodeUnitBytes, order2143, ignoreLeadingBOM)
	case aliasUCS43412:
		return withStrictDecode(&ucs4SwapEncoding{swap: swap3412}, utf32CodeUnitBytes, order3412, ignoreLeadingBOM)
	case aliasUCS2, aliasISO10646UCS2:
		return withStrictDecode(unicode.UTF16(unicode.BigEndian, unicode.IgnoreBOM), utf16CodeUnitBytes, orderBE2, ignoreLeadingBOM)
	}

	return nil
}

func loadEastAsianEncoding(norm string) enc.Encoding {
	// These normalized aliases preserve the exact recognized codec vocabulary.
	const (
		aliasEUCJP               = "eucjp"
		aliasXEUCJP              = "xeucjp"
		aliasCSEUCPKDFMTJAPANESE = "cseucpkdfmtjapanese"
		aliasSHIFTJIS            = "shiftjis"
		aliasCP932               = "cp932"
		aliasSJIS                = "sjis"
		aliasMS932               = "ms932"
		aliasMSKANJI             = "mskanji"
		aliasWINDOWS31J          = "windows31j"
		aliasXSJIS               = "xsjis"
		aliasCSSHIFTJIS          = "csshiftjis"
		aliasJIS                 = "jis"
		aliasISO2022JP           = "iso2022jp"
		aliasCSISO2022JP         = "csiso2022jp"
		aliasBIG5                = "big5"
		aliasCSBIG5              = "csbig5"
		aliasEUCKR               = "euckr"
		aliasCSEUCKR             = "cseuckr"
		aliasKSC56011987         = "ksc56011987"
		aliasCSKSC56011987       = "csksc56011987"
		aliasHZGB2312            = "hzgb2312"
	)

	switch norm {
	case aliasEUCJP, aliasXEUCJP, aliasCSEUCPKDFMTJAPANESE:
		return withStrictLegacyDecode(japanese.EUCJP)
	case aliasSHIFTJIS, aliasCP932, aliasSJIS, aliasMS932, aliasMSKANJI, aliasWINDOWS31J, aliasXSJIS, aliasCSSHIFTJIS:
		return withStrictLegacyDecode(japanese.ShiftJIS)
	case aliasJIS, aliasISO2022JP, aliasCSISO2022JP:
		return withStrictLegacyDecode(japanese.ISO2022JP)
	case aliasBIG5, aliasCSBIG5:
		return withStrictLegacyDecode(traditionalchinese.Big5)
	case aliasEUCKR, aliasCSEUCKR, aliasKSC56011987, aliasCSKSC56011987:
		return withStrictLegacyDecode(korean.EUCKR)
	case aliasHZGB2312:
		return withStrictLegacyDecode(simplifiedchinese.HZGB2312)
	}

	return nil
}

func loadISOEncoding(norm string) enc.Encoding {
	// These normalized aliases preserve the exact recognized codec vocabulary.
	const (
		aliasISO885910          = "iso885910"
		aliasLATIN6             = "latin6"
		aliasL6                 = "l6"
		aliasISOIR157           = "isoir157"
		aliasCSISOLATIN6        = "csisolatin6"
		aliasISO885913          = "iso885913"
		aliasISO885914          = "iso885914"
		aliasLATIN8             = "latin8"
		aliasL8                 = "l8"
		aliasISOIR199           = "isoir199"
		aliasCSISOLATIN8        = "csisolatin8"
		aliasISO885915          = "iso885915"
		aliasLATIN9             = "latin9"
		aliasL9                 = "l9"
		aliasCSISOLATIN9        = "csisolatin9"
		aliasISO885916          = "iso885916"
		aliasLATIN10            = "latin10"
		aliasL10                = "l10"
		aliasISO88592           = "iso88592"
		aliasISO885921987       = "iso885921987"
		aliasISOIR101           = "isoir101"
		aliasLATIN2             = "latin2"
		aliasL2                 = "l2"
		aliasCSISOLATIN2        = "csisolatin2"
		aliasISOLATIN2          = "isolatin2"
		aliasISO88593           = "iso88593"
		aliasISO885931988       = "iso885931988"
		aliasISOIR109           = "isoir109"
		aliasLATIN3             = "latin3"
		aliasL3                 = "l3"
		aliasCSISOLATIN3        = "csisolatin3"
		aliasISO88594           = "iso88594"
		aliasISO885941988       = "iso885941988"
		aliasISOIR110           = "isoir110"
		aliasLATIN4             = "latin4"
		aliasL4                 = "l4"
		aliasCSISOLATIN4        = "csisolatin4"
		aliasISO88595           = "iso88595"
		aliasISO885951988       = "iso885951988"
		aliasISOIR144           = "isoir144"
		aliasCYRILLIC           = "cyrillic"
		aliasCSISOLATINCYRILLIC = "csisolatincyrillic"
		aliasISO88596           = "iso88596"
		aliasISO885961987       = "iso885961987"
		aliasISOIR127           = "isoir127"
		aliasARABIC             = "arabic"
		aliasECMA114            = "ecma114"
		aliasASMO708            = "asmo708"
		aliasCSISOLATINARABIC   = "csisolatinarabic"
		aliasCSISO88596E        = "csiso88596e"
		aliasCSISO88596I        = "csiso88596i"
		aliasISO88597           = "iso88597"
		aliasISO885971987       = "iso885971987"
		aliasISOIR126           = "isoir126"
		aliasGREEK              = "greek"
		aliasGREEK8             = "greek8"
		aliasELOT928            = "elot928"
		aliasECMA118            = "ecma118"
		aliasCSISOLATINGREEK    = "csisolatingreek"
		aliasSUNEUGREEK         = "suneugreek"
		aliasISO88598           = "iso88598"
		aliasISO885981988       = "iso885981988"
		aliasISOIR138           = "isoir138"
		aliasHEBREW             = "hebrew"
		aliasCSISOLATINHEBREW   = "csisolatinhebrew"
		aliasCSISO88598E        = "csiso88598e"
		aliasCSISO88598I        = "csiso88598i"
		aliasLOGICAL            = "logical"
		aliasVISUAL             = "visual"
		aliasISO88599           = "iso88599"
		aliasISO885991989       = "iso885991989"
		aliasISOIR148           = "isoir148"
		aliasLATIN5             = "latin5"
		aliasL5                 = "l5"
		aliasCSISOLATIN5        = "csisolatin5"
		aliasISO885911          = "iso885911"
		aliasTIS620             = "tis620"
		aliasISO88591           = "iso88591"
		aliasISO885911987       = "iso885911987"
		aliasISOIR100           = "isoir100"
		aliasLATIN1             = "latin1"
		aliasL1                 = "l1"
		aliasIBM819             = "ibm819"
		aliasCP819              = "cp819"
		aliasCSISOLATIN1        = "csisolatin1"
		aliasISOLATIN1          = "isolatin1"
	)

	switch norm {
	case aliasISO885910, aliasLATIN6, aliasL6, aliasISOIR157, aliasCSISOLATIN6:
		return withC1Fallback(charmap.ISO8859_10)
	case aliasISO885913:
		return withC1Fallback(charmap.ISO8859_13)
	case aliasISO885914, aliasLATIN8, aliasL8, aliasISOIR199, aliasCSISOLATIN8:
		return withC1Fallback(charmap.ISO8859_14)
	case aliasISO885915, aliasLATIN9, aliasL9, aliasCSISOLATIN9:
		return withC1Fallback(charmap.ISO8859_15)
	case aliasISO885916, aliasLATIN10, aliasL10:
		return withC1Fallback(charmap.ISO8859_16)
	case aliasISO88592, aliasISO885921987, aliasISOIR101, aliasLATIN2, aliasL2, aliasCSISOLATIN2, aliasISOLATIN2:
		return withC1Fallback(charmap.ISO8859_2)
	case aliasISO88593, aliasISO885931988, aliasISOIR109, aliasLATIN3, aliasL3, aliasCSISOLATIN3:
		return withC1Fallback(charmap.ISO8859_3)
	case aliasISO88594, aliasISO885941988, aliasISOIR110, aliasLATIN4, aliasL4, aliasCSISOLATIN4:
		return withC1Fallback(charmap.ISO8859_4)
	case aliasISO88595, aliasISO885951988, aliasISOIR144, aliasCYRILLIC, aliasCSISOLATINCYRILLIC:
		return withC1Fallback(charmap.ISO8859_5)
	case aliasISO88596, aliasISO885961987, aliasISOIR127, aliasARABIC, aliasECMA114, aliasASMO708, aliasCSISOLATINARABIC, aliasCSISO88596E, aliasCSISO88596I:
		return withC1Fallback(charmap.ISO8859_6)
	case aliasISO88597, aliasISO885971987, aliasISOIR126, aliasGREEK, aliasGREEK8, aliasELOT928, aliasECMA118, aliasCSISOLATINGREEK, aliasSUNEUGREEK:
		return withC1Fallback(charmap.ISO8859_7)
	case aliasISO88598, aliasISO885981988, aliasISOIR138, aliasHEBREW, aliasCSISOLATINHEBREW, aliasCSISO88598E, aliasCSISO88598I, aliasLOGICAL, aliasVISUAL:
		return withC1Fallback(charmap.ISO8859_8)
	case aliasISO88599, aliasISO885991989, aliasISOIR148, aliasLATIN5, aliasL5, aliasCSISOLATIN5:
		return withC1Fallback(charmap.ISO8859_9)
	case aliasISO885911, aliasTIS620:
		// x/text/charmap does not expose ISO8859_11 directly; Windows-874 is
		// the closest Thai code page used in practice.
		return withC1Fallback(charmap.Windows874)
	case aliasISO88591, aliasISO885911987, aliasISOIR100, aliasLATIN1, aliasL1, aliasIBM819, aliasCP819, aliasCSISOLATIN1, aliasISOLATIN1:
		// True ISO-8859-1: bytes 0x80-0x9F map to the C1 controls
		// U+0080-U+009F, consistent with iso-8859-2..16 above. libxml2's XML
		// path uses the IANA/ISO codec here, not the Windows-1252 alias the
		// WHATWG HTML spec mandates (that leniency stays in the html/ package).
		return withC1Fallback(charmap.ISO8859_1)
	}

	return nil
}

func loadLegacyEncoding(norm string) enc.Encoding {
	// These normalized aliases preserve the exact recognized codec vocabulary.
	const (
		aliasCP437             = "cp437"
		aliasIBM437            = "ibm437"
		aliasCSPC8CODEPAGE437  = "cspc8codepage437"
		aliasCP866             = "cp866"
		aliasIBM866            = "ibm866"
		aliasCSIBM866          = "csibm866"
		aliasKOI8R             = "koi8r"
		aliasCSKOI8R           = "cskoi8r"
		aliasKOI8U             = "koi8u"
		aliasKOIR8U            = "koir8u"
		aliasMACINTOSH         = "macintosh"
		aliasMAC               = "mac"
		aliasCSMACINTOSH       = "csmacintosh"
		aliasMACINTOSHCYRILLIC = "macintoshcyrillic"
		aliasXMACCYRILLIC      = "xmaccyrillic"
		aliasMACCYRILLIC       = "maccyrillic"
		aliasWINDOWS1250       = "windows1250"
		aliasCP1250            = "cp1250"
		aliasWINDOWS1251       = "windows1251"
		aliasCP1251            = "cp1251"
		aliasWINDOWS1252       = "windows1252"
		aliasCP1252            = "cp1252"
		aliasXCP1252           = "xcp1252"
		aliasWINDOWS1253       = "windows1253"
		aliasCP1253            = "cp1253"
		aliasWINDOWS1254       = "windows1254"
		aliasCP1254            = "cp1254"
		aliasWINDOWS1255       = "windows1255"
		aliasCP1255            = "cp1255"
		aliasWINDOWS1256       = "windows1256"
		aliasCP1256            = "cp1256"
		aliasWINDOWS1257       = "windows1257"
		aliasCP1257            = "cp1257"
		aliasWINDOWS1258       = "windows1258"
		aliasCP1258            = "cp1258"
		aliasWINDOWS874        = "windows874"
		aliasCP874             = "cp874"
		aliasXUSERDEFINED      = "xuserdefined"
		aliasEBCDIC            = "ebcdic"
		aliasIBM037            = "ibm037"
		aliasCP037             = "cp037"
		aliasEBCDICUS          = "ebcdicus"
		aliasEBCDICCPUS        = "ebcdiccpus"
		aliasCSIBM037          = "csibm037"
		aliasIBM1047           = "ibm1047"
		aliasCP1047            = "cp1047"
		aliasIBM1140           = "ibm1140"
		aliasIBM01140          = "ibm01140"
		aliasCP1140            = "cp1140"
		aliasCCSID01140        = "ccsid01140"
		aliasIBM1141           = "ibm1141"
		aliasIBM01141          = "ibm01141"
		aliasCP1141            = "cp1141"
		aliasCCSID01141        = "ccsid01141"
	)

	switch norm {
	case aliasCP437, aliasIBM437, aliasCSPC8CODEPAGE437:
		return charmap.CodePage437
	case aliasCP866, aliasIBM866, aliasCSIBM866:
		return charmap.CodePage866
	case aliasKOI8R, aliasCSKOI8R:
		return charmap.KOI8R
	case aliasKOI8U, aliasKOIR8U:
		return charmap.KOI8U
	case aliasMACINTOSH, aliasMAC, aliasCSMACINTOSH:
		return charmap.Macintosh
	case aliasMACINTOSHCYRILLIC, aliasXMACCYRILLIC, aliasMACCYRILLIC:
		return charmap.MacintoshCyrillic
	case aliasWINDOWS1250, aliasCP1250:
		return withC1Fallback(charmap.Windows1250)
	case aliasWINDOWS1251, aliasCP1251:
		return withC1Fallback(charmap.Windows1251)
	case aliasWINDOWS1252, aliasCP1252, aliasXCP1252:
		return withC1Fallback(charmap.Windows1252)
	case aliasWINDOWS1253, aliasCP1253:
		return withC1Fallback(charmap.Windows1253)
	case aliasWINDOWS1254, aliasCP1254:
		return withC1Fallback(charmap.Windows1254)
	case aliasWINDOWS1255, aliasCP1255:
		return withC1Fallback(charmap.Windows1255)
	case aliasWINDOWS1256, aliasCP1256:
		return withC1Fallback(charmap.Windows1256)
	case aliasWINDOWS1257, aliasCP1257:
		return withC1Fallback(charmap.Windows1257)
	case aliasWINDOWS1258, aliasCP1258:
		return withC1Fallback(charmap.Windows1258)
	case aliasWINDOWS874, aliasCP874:
		return withC1Fallback(charmap.Windows874)
	case aliasXUSERDEFINED:
		return charmap.XUserDefined
	case aliasEBCDIC, aliasIBM037, aliasCP037, aliasEBCDICUS, aliasEBCDICCPUS, aliasCSIBM037:
		return charmap.CodePage037
	case aliasIBM1047, aliasCP1047:
		return charmap.CodePage1047
	case aliasIBM1140, aliasIBM01140, aliasCP1140, aliasCCSID01140:
		return charmap.CodePage1140
	case aliasIBM1141, aliasIBM01141, aliasCP1141, aliasCCSID01141:
		return newCodePage1141()
	}

	return nil
}
