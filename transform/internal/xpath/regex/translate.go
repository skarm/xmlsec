// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

// Package xpathregex translates XPath regular-expression syntax for the shared
// pattern engine. Translation validates edition-specific syntax; matching and
// resource accounting remain the caller's responsibility.
package xpathregex

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/skarm/xmlsec/internal/lexicon"
)

// XML NameStartChar as a character class (for use outside [])
const (
	xmlNameStartCharClass    = `[a-zA-Z_:\x{C0}-\x{D6}\x{D8}-\x{F6}\x{F8}-\x{2FF}\x{370}-\x{37D}\x{37F}-\x{1FFF}\x{200C}-\x{200D}\x{2070}-\x{218F}\x{2C00}-\x{2FEF}\x{3001}-\x{D7FF}\x{F900}-\x{FDCF}\x{FDF0}-\x{FFFD}\x{10000}-\x{EFFFF}]`
	xmlNameStartCharClassNeg = `[^a-zA-Z_:\x{C0}-\x{D6}\x{D8}-\x{F6}\x{F8}-\x{2FF}\x{370}-\x{37D}\x{37F}-\x{1FFF}\x{200C}-\x{200D}\x{2070}-\x{218F}\x{2C00}-\x{2FEF}\x{3001}-\x{D7FF}\x{F900}-\x{FDCF}\x{FDF0}-\x{FFFD}\x{10000}-\x{EFFFF}]`
)

// XML NameStartChar range (for use inside [])
const xmlNameStartCharRange = `a-zA-Z_:\x{C0}-\x{D6}\x{D8}-\x{F6}\x{F8}-\x{2FF}\x{370}-\x{37D}\x{37F}-\x{1FFF}\x{200C}-\x{200D}\x{2070}-\x{218F}\x{2C00}-\x{2FEF}\x{3001}-\x{D7FF}\x{F900}-\x{FDCF}\x{FDF0}-\x{FFFD}\x{10000}-\x{EFFFF}`

// Exact complement of xmlNameStartCharRange over U+0000–U+10FFFF.
const xmlNameStartCharRangeNeg = `\x{0}-\x{39}\x{3B}-\x{40}\x{5B}-\x{5E}\x{60}\x{7B}-\x{BF}\x{D7}\x{F7}\x{300}-\x{36F}\x{37E}\x{2000}-\x{200B}\x{200E}-\x{206F}\x{2190}-\x{2BFF}\x{2FF0}-\x{3000}\x{D800}-\x{F8FF}\x{FDD0}-\x{FDEF}\x{FFFE}-\x{FFFF}\x{F0000}-\x{10FFFF}`

// The XPath \c character class excludes U+0346. This applies only to pattern
// syntax; XML names use the shared internal/xmlchar predicates.
const (
	xpathRegexNameCharClass = `[a-zA-Z_:\x{C0}-\x{D6}\x{D8}-\x{F6}\x{F8}-\x{2FF}\x{370}-\x{37D}\x{37F}-\x{1FFF}\x{200C}-\x{200D}\x{2070}-\x{218F}\x{2C00}-\x{2FEF}\x{3001}-\x{D7FF}\x{F900}-\x{FDCF}\x{FDF0}-\x{FFFD}\x{10000}-\x{EFFFF}\-.0-9\x{B7}\x{300}-\x{345}\x{347}-\x{36F}\x{203F}-\x{2040}]`
	xpathRegexNameCharRange = `a-zA-Z_:\x{C0}-\x{D6}\x{D8}-\x{F6}\x{F8}-\x{2FF}\x{370}-\x{37D}\x{37F}-\x{1FFF}\x{200C}-\x{200D}\x{2070}-\x{218F}\x{2C00}-\x{2FEF}\x{3001}-\x{D7FF}\x{F900}-\x{FDCF}\x{FDF0}-\x{FFFD}\x{10000}-\x{EFFFF}\-.0-9\x{B7}\x{300}-\x{345}\x{347}-\x{36F}\x{203F}-\x{2040}`
)

const (
	xpathRegexNameCharClassNeg = `[^` + xpathRegexNameCharRange + `]`
	// The complement includes U+0346.
	xpathRegexNameCharRangeNeg = `\x{0}-\x{2C}\x{2F}\x{3B}-\x{40}\x{5B}-\x{5E}\x{60}\x{7B}-\x{B6}\x{B8}-\x{BF}\x{D7}\x{F7}\x{346}\x{37E}\x{2000}-\x{200B}\x{200E}-\x{203E}\x{2041}-\x{206F}\x{2190}-\x{2BFF}\x{2FF0}-\x{3000}\x{D800}-\x{F8FF}\x{FDD0}-\x{FDEF}\x{FFFE}-\x{FFFF}\x{F0000}-\x{10FFFF}`
)

// Unicode 17.0.0 block ranges from the Unicode Character Database:
// https://www.unicode.org/Public/17.0.0/ucd/Blocks.txt
// Copyright © 2025 Unicode, Inc. See licenses/Unicode-3.0.txt.
// XML Schema normalized names retain case and hyphens. Historical aliases
// from Unicode 3.1 remain available. Surrogate blocks never match XML characters.
//
//nolint:gochecknoglobals // Read-only Unicode data avoids reconstructing the table for each compilation.
var unicodeBlocks = map[string]string{
	"Adlam":                                `\x{1E900}-\x{1E95F}`,
	"AegeanNumbers":                        `\x{10100}-\x{1013F}`,
	"Ahom":                                 `\x{11700}-\x{1174F}`,
	"AlchemicalSymbols":                    `\x{1F700}-\x{1F77F}`,
	"AlphabeticPresentationForms":          `\x{FB00}-\x{FB4F}`,
	"AnatolianHieroglyphs":                 `\x{14400}-\x{1467F}`,
	"AncientGreekMusicalNotation":          `\x{1D200}-\x{1D24F}`,
	"AncientGreekNumbers":                  `\x{10140}-\x{1018F}`,
	"AncientSymbols":                       `\x{10190}-\x{101CF}`,
	"Arabic":                               `\x{0600}-\x{06FF}`,
	"ArabicExtended-A":                     `\x{08A0}-\x{08FF}`,
	"ArabicExtended-B":                     `\x{0870}-\x{089F}`,
	"ArabicExtended-C":                     `\x{10EC0}-\x{10EFF}`,
	"ArabicMathematicalAlphabeticSymbols":  `\x{1EE00}-\x{1EEFF}`,
	"ArabicPresentationForms-A":            `\x{FB50}-\x{FDFF}`,
	"ArabicPresentationForms-B":            `\x{FE70}-\x{FEFF}`,
	"ArabicSupplement":                     `\x{0750}-\x{077F}`,
	"Armenian":                             `\x{0530}-\x{058F}`,
	"Arrows":                               `\x{2190}-\x{21FF}`,
	"Avestan":                              `\x{10B00}-\x{10B3F}`,
	"Balinese":                             `\x{1B00}-\x{1B7F}`,
	"Bamum":                                `\x{A6A0}-\x{A6FF}`,
	"BamumSupplement":                      `\x{16800}-\x{16A3F}`,
	"BasicLatin":                           `\x{0000}-\x{007F}`,
	"BassaVah":                             `\x{16AD0}-\x{16AFF}`,
	"Batak":                                `\x{1BC0}-\x{1BFF}`,
	"Bengali":                              `\x{0980}-\x{09FF}`,
	"BeriaErfe":                            `\x{16EA0}-\x{16EDF}`,
	"Bhaiksuki":                            `\x{11C00}-\x{11C6F}`,
	"BlockElements":                        `\x{2580}-\x{259F}`,
	"Bopomofo":                             `\x{3100}-\x{312F}`,
	"BopomofoExtended":                     `\x{31A0}-\x{31BF}`,
	"BoxDrawing":                           `\x{2500}-\x{257F}`,
	"Brahmi":                               `\x{11000}-\x{1107F}`,
	"BraillePatterns":                      `\x{2800}-\x{28FF}`,
	"Buginese":                             `\x{1A00}-\x{1A1F}`,
	"Buhid":                                `\x{1740}-\x{175F}`,
	"ByzantineMusicalSymbols":              `\x{1D000}-\x{1D0FF}`,
	"CJKCompatibility":                     `\x{3300}-\x{33FF}`,
	"CJKCompatibilityForms":                `\x{FE30}-\x{FE4F}`,
	"CJKCompatibilityIdeographs":           `\x{F900}-\x{FAFF}`,
	"CJKCompatibilityIdeographsSupplement": `\x{2F800}-\x{2FA1F}`,
	"CJKRadicalsSupplement":                `\x{2E80}-\x{2EFF}`,
	"CJKStrokes":                           `\x{31C0}-\x{31EF}`,
	"CJKSymbolsandPunctuation":             `\x{3000}-\x{303F}`,
	"CJKUnifiedIdeographs":                 `\x{4E00}-\x{9FFF}`,
	"CJKUnifiedIdeographsExtensionA":       `\x{3400}-\x{4DBF}`,
	"CJKUnifiedIdeographsExtensionB":       `\x{20000}-\x{2A6DF}`,
	"CJKUnifiedIdeographsExtensionC":       `\x{2A700}-\x{2B73F}`,
	"CJKUnifiedIdeographsExtensionD":       `\x{2B740}-\x{2B81F}`,
	"CJKUnifiedIdeographsExtensionE":       `\x{2B820}-\x{2CEAF}`,
	"CJKUnifiedIdeographsExtensionF":       `\x{2CEB0}-\x{2EBEF}`,
	"CJKUnifiedIdeographsExtensionG":       `\x{30000}-\x{3134F}`,
	"CJKUnifiedIdeographsExtensionH":       `\x{31350}-\x{323AF}`,
	"CJKUnifiedIdeographsExtensionI":       `\x{2EBF0}-\x{2EE5F}`,
	"CJKUnifiedIdeographsExtensionJ":       `\x{323B0}-\x{3347F}`,
	"Carian":                               `\x{102A0}-\x{102DF}`,
	"CaucasianAlbanian":                    `\x{10530}-\x{1056F}`,
	"Chakma":                               `\x{11100}-\x{1114F}`,
	"Cham":                                 `\x{AA00}-\x{AA5F}`,
	"Cherokee":                             `\x{13A0}-\x{13FF}`,
	"CherokeeSupplement":                   `\x{AB70}-\x{ABBF}`,
	"ChessSymbols":                         `\x{1FA00}-\x{1FA6F}`,
	"Chorasmian":                           `\x{10FB0}-\x{10FDF}`,
	"CombiningDiacriticalMarks":            `\x{0300}-\x{036F}`,
	"CombiningDiacriticalMarksExtended":    `\x{1AB0}-\x{1AFF}`,
	"CombiningDiacriticalMarksSupplement":  `\x{1DC0}-\x{1DFF}`,
	"CombiningDiacriticalMarksforSymbols":  `\x{20D0}-\x{20FF}`,
	"CombiningHalfMarks":                   `\x{FE20}-\x{FE2F}`,
	"CombiningMarksforSymbols":             `\x{20D0}-\x{20FF}`,
	"CommonIndicNumberForms":               `\x{A830}-\x{A83F}`,
	"ControlPictures":                      `\x{2400}-\x{243F}`,
	"Coptic":                               `\x{2C80}-\x{2CFF}`,
	"CopticEpactNumbers":                   `\x{102E0}-\x{102FF}`,
	"CountingRodNumerals":                  `\x{1D360}-\x{1D37F}`,
	"Cuneiform":                            `\x{12000}-\x{123FF}`,
	"CuneiformNumbersandPunctuation":       `\x{12400}-\x{1247F}`,
	"CurrencySymbols":                      `\x{20A0}-\x{20CF}`,
	"CypriotSyllabary":                     `\x{10800}-\x{1083F}`,
	"Cypro-Minoan":                         `\x{12F90}-\x{12FFF}`,
	"Cyrillic":                             `\x{0400}-\x{04FF}`,
	"CyrillicExtended-A":                   `\x{2DE0}-\x{2DFF}`,
	"CyrillicExtended-B":                   `\x{A640}-\x{A69F}`,
	"CyrillicExtended-C":                   `\x{1C80}-\x{1C8F}`,
	"CyrillicExtended-D":                   `\x{1E030}-\x{1E08F}`,
	"CyrillicSupplement":                   `\x{0500}-\x{052F}`,
	"Deseret":                              `\x{10400}-\x{1044F}`,
	"Devanagari":                           `\x{0900}-\x{097F}`,
	"DevanagariExtended":                   `\x{A8E0}-\x{A8FF}`,
	"DevanagariExtended-A":                 `\x{11B00}-\x{11B5F}`,
	"Dingbats":                             `\x{2700}-\x{27BF}`,
	"DivesAkuru":                           `\x{11900}-\x{1195F}`,
	"Dogra":                                `\x{11800}-\x{1184F}`,
	"DominoTiles":                          `\x{1F030}-\x{1F09F}`,
	"Duployan":                             `\x{1BC00}-\x{1BC9F}`,
	"EarlyDynasticCuneiform":               `\x{12480}-\x{1254F}`,
	"EgyptianHieroglyphFormatControls":     `\x{13430}-\x{1345F}`,
	"EgyptianHieroglyphs":                  `\x{13000}-\x{1342F}`,
	"EgyptianHieroglyphsExtended-A":        `\x{13460}-\x{143FF}`,
	"Elbasan":                              `\x{10500}-\x{1052F}`,
	"Elymaic":                              `\x{10FE0}-\x{10FFF}`,
	"Emoticons":                            `\x{1F600}-\x{1F64F}`,
	"EnclosedAlphanumericSupplement":       `\x{1F100}-\x{1F1FF}`,
	"EnclosedAlphanumerics":                `\x{2460}-\x{24FF}`,
	"EnclosedCJKLettersandMonths":          `\x{3200}-\x{32FF}`,
	"EnclosedIdeographicSupplement":        `\x{1F200}-\x{1F2FF}`,
	"Ethiopic":                             `\x{1200}-\x{137F}`,
	"EthiopicExtended":                     `\x{2D80}-\x{2DDF}`,
	"EthiopicExtended-A":                   `\x{AB00}-\x{AB2F}`,
	"EthiopicExtended-B":                   `\x{1E7E0}-\x{1E7FF}`,
	"EthiopicSupplement":                   `\x{1380}-\x{139F}`,
	"Garay":                                `\x{10D40}-\x{10D8F}`,
	"GeneralPunctuation":                   `\x{2000}-\x{206F}`,
	"GeometricShapes":                      `\x{25A0}-\x{25FF}`,
	"GeometricShapesExtended":              `\x{1F780}-\x{1F7FF}`,
	"Georgian":                             `\x{10A0}-\x{10FF}`,
	"GeorgianExtended":                     `\x{1C90}-\x{1CBF}`,
	"GeorgianSupplement":                   `\x{2D00}-\x{2D2F}`,
	"Glagolitic":                           `\x{2C00}-\x{2C5F}`,
	"GlagoliticSupplement":                 `\x{1E000}-\x{1E02F}`,
	"Gothic":                               `\x{10330}-\x{1034F}`,
	"Grantha":                              `\x{11300}-\x{1137F}`,
	"Greek":                                `\x{0370}-\x{03FF}`,
	"GreekExtended":                        `\x{1F00}-\x{1FFF}`,
	"GreekandCoptic":                       `\x{0370}-\x{03FF}`,
	"Gujarati":                             `\x{0A80}-\x{0AFF}`,
	"GunjalaGondi":                         `\x{11D60}-\x{11DAF}`,
	"Gurmukhi":                             `\x{0A00}-\x{0A7F}`,
	"GurungKhema":                          `\x{16100}-\x{1613F}`,
	"HalfwidthandFullwidthForms":           `\x{FF00}-\x{FFEF}`,
	"HangulCompatibilityJamo":              `\x{3130}-\x{318F}`,
	"HangulJamo":                           `\x{1100}-\x{11FF}`,
	"HangulJamoExtended-A":                 `\x{A960}-\x{A97F}`,
	"HangulJamoExtended-B":                 `\x{D7B0}-\x{D7FF}`,
	"HangulSyllables":                      `\x{AC00}-\x{D7AF}`,
	"HanifiRohingya":                       `\x{10D00}-\x{10D3F}`,
	"Hanunoo":                              `\x{1720}-\x{173F}`,
	"Hatran":                               `\x{108E0}-\x{108FF}`,
	"Hebrew":                               `\x{0590}-\x{05FF}`,
	"HighPrivateUseSurrogates":             `\x{DB80}-\x{DBFF}`,
	"HighSurrogates":                       `\x{D800}-\x{DB7F}`,
	"Hiragana":                             `\x{3040}-\x{309F}`,
	"IPAExtensions":                        `\x{0250}-\x{02AF}`,
	"IdeographicDescriptionCharacters":     `\x{2FF0}-\x{2FFF}`,
	"IdeographicSymbolsandPunctuation":     `\x{16FE0}-\x{16FFF}`,
	"ImperialAramaic":                      `\x{10840}-\x{1085F}`,
	"IndicSiyaqNumbers":                    `\x{1EC70}-\x{1ECBF}`,
	"InscriptionalPahlavi":                 `\x{10B60}-\x{10B7F}`,
	"InscriptionalParthian":                `\x{10B40}-\x{10B5F}`,
	"Javanese":                             `\x{A980}-\x{A9DF}`,
	"Kaithi":                               `\x{11080}-\x{110CF}`,
	"KaktovikNumerals":                     `\x{1D2C0}-\x{1D2DF}`,
	"KanaExtended-A":                       `\x{1B100}-\x{1B12F}`,
	"KanaExtended-B":                       `\x{1AFF0}-\x{1AFFF}`,
	"KanaSupplement":                       `\x{1B000}-\x{1B0FF}`,
	"Kanbun":                               `\x{3190}-\x{319F}`,
	"KangxiRadicals":                       `\x{2F00}-\x{2FDF}`,
	"Kannada":                              `\x{0C80}-\x{0CFF}`,
	"Katakana":                             `\x{30A0}-\x{30FF}`,
	"KatakanaPhoneticExtensions":           `\x{31F0}-\x{31FF}`,
	"Kawi":                                 `\x{11F00}-\x{11F5F}`,
	"KayahLi":                              `\x{A900}-\x{A92F}`,
	"Kharoshthi":                           `\x{10A00}-\x{10A5F}`,
	"KhitanSmallScript":                    `\x{18B00}-\x{18CFF}`,
	"Khmer":                                `\x{1780}-\x{17FF}`,
	"KhmerSymbols":                         `\x{19E0}-\x{19FF}`,
	"Khojki":                               `\x{11200}-\x{1124F}`,
	"Khudawadi":                            `\x{112B0}-\x{112FF}`,
	"KiratRai":                             `\x{16D40}-\x{16D7F}`,
	"Lao":                                  `\x{0E80}-\x{0EFF}`,
	"Latin-1Supplement":                    `\x{0080}-\x{00FF}`,
	"LatinExtended-A":                      `\x{0100}-\x{017F}`,
	"LatinExtended-B":                      `\x{0180}-\x{024F}`,
	"LatinExtended-C":                      `\x{2C60}-\x{2C7F}`,
	"LatinExtended-D":                      `\x{A720}-\x{A7FF}`,
	"LatinExtended-E":                      `\x{AB30}-\x{AB6F}`,
	"LatinExtended-F":                      `\x{10780}-\x{107BF}`,
	"LatinExtended-G":                      `\x{1DF00}-\x{1DFFF}`,
	"LatinExtendedAdditional":              `\x{1E00}-\x{1EFF}`,
	"Lepcha":                               `\x{1C00}-\x{1C4F}`,
	"LetterlikeSymbols":                    `\x{2100}-\x{214F}`,
	"Limbu":                                `\x{1900}-\x{194F}`,
	"LinearA":                              `\x{10600}-\x{1077F}`,
	"LinearBIdeograms":                     `\x{10080}-\x{100FF}`,
	"LinearBSyllabary":                     `\x{10000}-\x{1007F}`,
	"Lisu":                                 `\x{A4D0}-\x{A4FF}`,
	"LisuSupplement":                       `\x{11FB0}-\x{11FBF}`,
	"LowSurrogates":                        `\x{DC00}-\x{DFFF}`,
	"Lycian":                               `\x{10280}-\x{1029F}`,
	"Lydian":                               `\x{10920}-\x{1093F}`,
	"Mahajani":                             `\x{11150}-\x{1117F}`,
	"MahjongTiles":                         `\x{1F000}-\x{1F02F}`,
	"Makasar":                              `\x{11EE0}-\x{11EFF}`,
	"Malayalam":                            `\x{0D00}-\x{0D7F}`,
	"Mandaic":                              `\x{0840}-\x{085F}`,
	"Manichaean":                           `\x{10AC0}-\x{10AFF}`,
	"Marchen":                              `\x{11C70}-\x{11CBF}`,
	"MasaramGondi":                         `\x{11D00}-\x{11D5F}`,
	"MathematicalAlphanumericSymbols":      `\x{1D400}-\x{1D7FF}`,
	"MathematicalOperators":                `\x{2200}-\x{22FF}`,
	"MayanNumerals":                        `\x{1D2E0}-\x{1D2FF}`,
	"Medefaidrin":                          `\x{16E40}-\x{16E9F}`,
	"MeeteiMayek":                          `\x{ABC0}-\x{ABFF}`,
	"MeeteiMayekExtensions":                `\x{AAE0}-\x{AAFF}`,
	"MendeKikakui":                         `\x{1E800}-\x{1E8DF}`,
	"MeroiticCursive":                      `\x{109A0}-\x{109FF}`,
	"MeroiticHieroglyphs":                  `\x{10980}-\x{1099F}`,
	"Miao":                                 `\x{16F00}-\x{16F9F}`,
	"MiscellaneousMathematicalSymbols-A":   `\x{27C0}-\x{27EF}`,
	"MiscellaneousMathematicalSymbols-B":   `\x{2980}-\x{29FF}`,
	"MiscellaneousSymbols":                 `\x{2600}-\x{26FF}`,
	"MiscellaneousSymbolsSupplement":       `\x{1CEC0}-\x{1CEFF}`,
	"MiscellaneousSymbolsandArrows":        `\x{2B00}-\x{2BFF}`,
	"MiscellaneousSymbolsandPictographs":   `\x{1F300}-\x{1F5FF}`,
	"MiscellaneousTechnical":               `\x{2300}-\x{23FF}`,
	"Modi":                                 `\x{11600}-\x{1165F}`,
	"ModifierToneLetters":                  `\x{A700}-\x{A71F}`,
	"Mongolian":                            `\x{1800}-\x{18AF}`,
	"MongolianSupplement":                  `\x{11660}-\x{1167F}`,
	"Mro":                                  `\x{16A40}-\x{16A6F}`,
	"Multani":                              `\x{11280}-\x{112AF}`,
	"MusicalSymbols":                       `\x{1D100}-\x{1D1FF}`,
	"Myanmar":                              `\x{1000}-\x{109F}`,
	"MyanmarExtended-A":                    `\x{AA60}-\x{AA7F}`,
	"MyanmarExtended-B":                    `\x{A9E0}-\x{A9FF}`,
	"MyanmarExtended-C":                    `\x{116D0}-\x{116FF}`,
	"NKo":                                  `\x{07C0}-\x{07FF}`,
	"Nabataean":                            `\x{10880}-\x{108AF}`,
	"NagMundari":                           `\x{1E4D0}-\x{1E4FF}`,
	"Nandinagari":                          `\x{119A0}-\x{119FF}`,
	"NewTaiLue":                            `\x{1980}-\x{19DF}`,
	"Newa":                                 `\x{11400}-\x{1147F}`,
	"NumberForms":                          `\x{2150}-\x{218F}`,
	"Nushu":                                `\x{1B170}-\x{1B2FF}`,
	"NyiakengPuachueHmong":                 `\x{1E100}-\x{1E14F}`,
	"Ogham":                                `\x{1680}-\x{169F}`,
	"OlChiki":                              `\x{1C50}-\x{1C7F}`,
	"OlOnal":                               `\x{1E5D0}-\x{1E5FF}`,
	"OldHungarian":                         `\x{10C80}-\x{10CFF}`,
	"OldItalic":                            `\x{10300}-\x{1032F}`,
	"OldNorthArabian":                      `\x{10A80}-\x{10A9F}`,
	"OldPermic":                            `\x{10350}-\x{1037F}`,
	"OldPersian":                           `\x{103A0}-\x{103DF}`,
	"OldSogdian":                           `\x{10F00}-\x{10F2F}`,
	"OldSouthArabian":                      `\x{10A60}-\x{10A7F}`,
	"OldTurkic":                            `\x{10C00}-\x{10C4F}`,
	"OldUyghur":                            `\x{10F70}-\x{10FAF}`,
	"OpticalCharacterRecognition":          `\x{2440}-\x{245F}`,
	"Oriya":                                `\x{0B00}-\x{0B7F}`,
	"OrnamentalDingbats":                   `\x{1F650}-\x{1F67F}`,
	"Osage":                                `\x{104B0}-\x{104FF}`,
	"Osmanya":                              `\x{10480}-\x{104AF}`,
	"OttomanSiyaqNumbers":                  `\x{1ED00}-\x{1ED4F}`,
	"PahawhHmong":                          `\x{16B00}-\x{16B8F}`,
	"Palmyrene":                            `\x{10860}-\x{1087F}`,
	"PauCinHau":                            `\x{11AC0}-\x{11AFF}`,
	"Phags-pa":                             `\x{A840}-\x{A87F}`,
	"PhaistosDisc":                         `\x{101D0}-\x{101FF}`,
	"Phoenician":                           `\x{10900}-\x{1091F}`,
	"PhoneticExtensions":                   `\x{1D00}-\x{1D7F}`,
	"PhoneticExtensionsSupplement":         `\x{1D80}-\x{1DBF}`,
	"PlayingCards":                         `\x{1F0A0}-\x{1F0FF}`,
	"PrivateUse":                           `\x{E000}-\x{F8FF}\x{F0000}-\x{FFFFD}\x{100000}-\x{10FFFD}`,
	"PrivateUseArea":                       `\x{E000}-\x{F8FF}`,
	"PsalterPahlavi":                       `\x{10B80}-\x{10BAF}`,
	"Rejang":                               `\x{A930}-\x{A95F}`,
	"RumiNumeralSymbols":                   `\x{10E60}-\x{10E7F}`,
	"Runic":                                `\x{16A0}-\x{16FF}`,
	"Samaritan":                            `\x{0800}-\x{083F}`,
	"Saurashtra":                           `\x{A880}-\x{A8DF}`,
	"Sharada":                              `\x{11180}-\x{111DF}`,
	"SharadaSupplement":                    `\x{11B60}-\x{11B7F}`,
	"Shavian":                              `\x{10450}-\x{1047F}`,
	"ShorthandFormatControls":              `\x{1BCA0}-\x{1BCAF}`,
	"Siddham":                              `\x{11580}-\x{115FF}`,
	"Sidetic":                              `\x{10940}-\x{1095F}`,
	"Sinhala":                              `\x{0D80}-\x{0DFF}`,
	"SinhalaArchaicNumbers":                `\x{111E0}-\x{111FF}`,
	"SmallFormVariants":                    `\x{FE50}-\x{FE6F}`,
	"SmallKanaExtension":                   `\x{1B130}-\x{1B16F}`,
	"Sogdian":                              `\x{10F30}-\x{10F6F}`,
	"SoraSompeng":                          `\x{110D0}-\x{110FF}`,
	"Soyombo":                              `\x{11A50}-\x{11AAF}`,
	"SpacingModifierLetters":               `\x{02B0}-\x{02FF}`,
	"Specials":                             `\x{FFF0}-\x{FFFF}`,
	"Sundanese":                            `\x{1B80}-\x{1BBF}`,
	"SundaneseSupplement":                  `\x{1CC0}-\x{1CCF}`,
	"Sunuwar":                              `\x{11BC0}-\x{11BFF}`,
	"SuperscriptsandSubscripts":            `\x{2070}-\x{209F}`,
	"SupplementalArrows-A":                 `\x{27F0}-\x{27FF}`,
	"SupplementalArrows-B":                 `\x{2900}-\x{297F}`,
	"SupplementalArrows-C":                 `\x{1F800}-\x{1F8FF}`,
	"SupplementalMathematicalOperators":    `\x{2A00}-\x{2AFF}`,
	"SupplementalPunctuation":              `\x{2E00}-\x{2E7F}`,
	"SupplementalSymbolsandPictographs":    `\x{1F900}-\x{1F9FF}`,
	"SupplementaryPrivateUseArea-A":        `\x{F0000}-\x{FFFFF}`,
	"SupplementaryPrivateUseArea-B":        `\x{100000}-\x{10FFFF}`,
	"SuttonSignWriting":                    `\x{1D800}-\x{1DAAF}`,
	"SylotiNagri":                          `\x{A800}-\x{A82F}`,
	"SymbolsandPictographsExtended-A":      `\x{1FA70}-\x{1FAFF}`,
	"SymbolsforLegacyComputing":            `\x{1FB00}-\x{1FBFF}`,
	"SymbolsforLegacyComputingSupplement":  `\x{1CC00}-\x{1CEBF}`,
	"Syriac":                               `\x{0700}-\x{074F}`,
	"SyriacSupplement":                     `\x{0860}-\x{086F}`,
	"Tagalog":                              `\x{1700}-\x{171F}`,
	"Tagbanwa":                             `\x{1760}-\x{177F}`,
	"Tags":                                 `\x{E0000}-\x{E007F}`,
	"TaiLe":                                `\x{1950}-\x{197F}`,
	"TaiTham":                              `\x{1A20}-\x{1AAF}`,
	"TaiViet":                              `\x{AA80}-\x{AADF}`,
	"TaiXuanJingSymbols":                   `\x{1D300}-\x{1D35F}`,
	"TaiYo":                                `\x{1E6C0}-\x{1E6FF}`,
	"Takri":                                `\x{11680}-\x{116CF}`,
	"Tamil":                                `\x{0B80}-\x{0BFF}`,
	"TamilSupplement":                      `\x{11FC0}-\x{11FFF}`,
	"Tangsa":                               `\x{16A70}-\x{16ACF}`,
	"Tangut":                               `\x{17000}-\x{187FF}`,
	"TangutComponents":                     `\x{18800}-\x{18AFF}`,
	"TangutComponentsSupplement":           `\x{18D80}-\x{18DFF}`,
	"TangutSupplement":                     `\x{18D00}-\x{18D7F}`,
	"Telugu":                               `\x{0C00}-\x{0C7F}`,
	"Thaana":                               `\x{0780}-\x{07BF}`,
	"Thai":                                 `\x{0E00}-\x{0E7F}`,
	"Tibetan":                              `\x{0F00}-\x{0FFF}`,
	"Tifinagh":                             `\x{2D30}-\x{2D7F}`,
	"Tirhuta":                              `\x{11480}-\x{114DF}`,
	"Todhri":                               `\x{105C0}-\x{105FF}`,
	"TolongSiki":                           `\x{11DB0}-\x{11DEF}`,
	"Toto":                                 `\x{1E290}-\x{1E2BF}`,
	"TransportandMapSymbols":               `\x{1F680}-\x{1F6FF}`,
	"Tulu-Tigalari":                        `\x{11380}-\x{113FF}`,
	"Ugaritic":                             `\x{10380}-\x{1039F}`,
	"UnifiedCanadianAboriginalSyllabics":   `\x{1400}-\x{167F}`,
	"UnifiedCanadianAboriginalSyllabicsExtended":   `\x{18B0}-\x{18FF}`,
	"UnifiedCanadianAboriginalSyllabicsExtended-A": `\x{11AB0}-\x{11ABF}`,
	"Vai":                          `\x{A500}-\x{A63F}`,
	"VariationSelectors":           `\x{FE00}-\x{FE0F}`,
	"VariationSelectorsSupplement": `\x{E0100}-\x{E01EF}`,
	"VedicExtensions":              `\x{1CD0}-\x{1CFF}`,
	"VerticalForms":                `\x{FE10}-\x{FE1F}`,
	"Vithkuqi":                     `\x{10570}-\x{105BF}`,
	"Wancho":                       `\x{1E2C0}-\x{1E2FF}`,
	"WarangCiti":                   `\x{118A0}-\x{118FF}`,
	"Yezidi":                       `\x{10E80}-\x{10EBF}`,
	"YiRadicals":                   `\x{A490}-\x{A4CF}`,
	"YiSyllables":                  `\x{A000}-\x{A48F}`,
	"YijingHexagramSymbols":        `\x{4DC0}-\x{4DFF}`,
	"ZanabazarSquare":              `\x{11A00}-\x{11A4F}`,
	"ZnamennyMusicalNotation":      `\x{1CF00}-\x{1CFCF}`,
}

// Translate converts an XPath/XQuery regex pattern (fn:matches/tokenize/replace)
// into the shared Go pattern grammar. In this flavor '^' and '$' are anchors and the pattern
// is not implicitly anchored.
func Translate(pattern string, dotAll, ignoreCase bool) (string, error) {
	return translateXPathRegex(pattern, dotAll, ignoreCase)
}

// ValidateXSD10 rejects the interior literal hyphens permitted by XSD 1.1
// but excluded from XML Schema 1.0 character groups. Existing validation
// independently checks escapes, endpoints and subtraction structure.
func ValidateXSD10(pattern string) error {
	var classes []xsd10Class

	for i := 0; i < len(pattern); {
		ch, width := utf8.DecodeRuneInString(pattern[i:])

		i += width
		if ch == '\\' {
			next, single := xsd10Escape(pattern, i)
			i = next

			if len(classes) > 0 {
				if err := classes[len(classes)-1].escaped(single); err != nil {
					return err
				}
			}

			continue
		}

		switch ch {
		case '[':
			classes = append(classes, xsd10Class{first: true})
		case ']':
			if len(classes) > 0 {
				classes = classes[:len(classes)-1]
			}
		default:
			if len(classes) == 0 {
				continue
			}

			next := byte(0)
			if i < len(pattern) {
				next = pattern[i]
			}

			if err := classes[len(classes)-1].character(ch, next); err != nil {
				return err
			}
		}
	}

	return nil
}

type xsd10Class struct {
	first    bool
	negated  bool
	single   bool
	endpoint bool
}

func (c *xsd10Class) escaped(single bool) error {
	if c.endpoint && !single {
		return invalidXSD10Hyphen()
	}

	c.first = false
	c.single, c.endpoint = single && !c.endpoint, false

	return nil
}

func (c *xsd10Class) character(ch rune, next byte) error {
	if ch == '^' && c.first && !c.negated {
		c.negated = true
		return nil
	}

	if ch == '-' {
		if !c.first && next != 0 && next != ']' && next != '[' {
			if !c.single {
				return invalidXSD10Hyphen()
			}

			c.single, c.endpoint = false, true

			return nil
		}

		c.first, c.single, c.endpoint = false, false, false

		return nil
	}

	c.first = false
	c.single, c.endpoint = !c.endpoint, false

	return nil
}

// Validate enforces the XPath/XSD pattern grammar before compilation.
func Validate(pattern string, allowBackrefs bool) error {
	return validateXPathRegex(pattern, allowBackrefs)
}

// HasBackrefs reports whether the pattern contains a back-reference.
func HasBackrefs(pattern string) bool { return hasXPathBackrefs(pattern) }

// RejectPerlSpecific rejects Perl-only constructs not allowed in XPath regex.
func RejectPerlSpecific(pattern string) error { return rejectPerlSpecific(pattern) }

func xsd10Escape(pattern string, at int) (int, bool) {
	if at >= len(pattern) {
		return at, false
	}

	escaped, size := utf8.DecodeRuneInString(pattern[at:])
	at += size

	single := !strings.ContainsRune("pPdDsSwWiIcC", escaped)
	if (escaped == 'p' || escaped == 'P') && at < len(pattern) && pattern[at] == '{' {
		if end := strings.IndexByte(pattern[at:], '}'); end >= 0 {
			at += end + 1
		}
	}

	return at, single
}

func invalidXSD10Hyphen() error {
	return &regexError{Code: lexicon.ErrFORX0002, Message: "interior literal hyphen is unavailable in XML Schema 1.0"}
}

// translateXPathRegex translates an XPath/XML Schema regex pattern into a
// pattern with explicit XML Schema character semantics. Handles:
//   - \p{IsBlockName} / \P{IsBlockName} → (negated) Unicode block character range
//   - \p{Category} → Go-compatible \p{Category} (pass-through)
//   - \i / \I → XML NameStartChar / negated
//   - \c / \C → XML NameChar / negated
//   - \d \D \w \W \s \S → XSD-semantics equivalents
//   - '.' → [^\n\r] (or [\s\S] when dotAll)
//
// It does NOT expand character class subtraction ([a-z-[aeiou]]); that is passed
// through to the shared engine, which handles subtraction directly. It also does NOT reject
// Perl-specific constructs or validate back-references — call RejectPerlSpecific
// and Validate separately for those checks.
func translateXPathRegex(pattern string, dotAll, ignoreCase bool) (string, error) {
	var b strings.Builder

	runes := []rune(pattern)
	for i := 0; i < len(runes); {
		r := runes[i]
		if r == '\\' && i+1 < len(runes) {
			replacement, consumed, err := translateRegexEscape(runes, i, ignoreCase)
			if err != nil {
				return "", err
			}

			b.WriteString(replacement)

			i += consumed

			continue
		}

		if r == '[' {
			class, consumed, err := translateCharClass(runes, i)
			if err != nil {
				return "", err
			}

			b.WriteString(class)

			i += consumed

			continue
		}

		if r == '.' {
			// XPath's dot excludes both CR and LF unless dotAll is set.
			if dotAll {
				b.WriteString(`[\s\S]`)
			} else {
				b.WriteString(`[^\n\r]`)
			}
		} else {
			b.WriteRune(r)
		}

		i++
	}

	return b.String(), nil
}

func translateRegexEscape(runes []rune, start int, ignoreCase bool) (string, int, error) {
	next := runes[start+1]
	if (next == 'p' || next == 'P') && start+2 < len(runes) && runes[start+2] == '{' {
		end := findClosingBrace(runes, start+3)
		if end < 0 {
			return "", 0, fmt.Errorf("unterminated \\%c{ at position %d", next, start)
		}

		replacement, err := translateUnicodeProperty(string(runes[start+3:end]), next == 'P')
		if err != nil {
			return "", 0, err
		}

		if ignoreCase {
			replacement = "(?-i:" + replacement + ")"
		}

		return replacement, end - start + 1, nil
	}

	switch next {
	case 'i':
		return xmlNameStartCharClass, 2, nil
	case 'I':
		return xmlNameStartCharClassNeg, 2, nil
	case 'c':
		return xpathRegexNameCharClass, 2, nil
	case 'C':
		return xpathRegexNameCharClassNeg, 2, nil
	case 'd':
		return `\p{Nd}`, 2, nil
	case 'D':
		return `[^\p{Nd}]`, 2, nil
	case 'w':
		return `[^\p{P}\p{Z}\p{C}]`, 2, nil
	case 'W':
		return `[\p{P}\p{Z}\p{C}]`, 2, nil
	case 's':
		return `[\t\n\r ]`, 2, nil
	case 'S':
		return `[^\t\n\r ]`, 2, nil
	default:
		return string(runes[start : start+2]), 2, nil
	}
}

// translateCharClass translates a character class, handling subtraction.
// Returns the translated class and the number of runes consumed.
func translateCharClass(runes []rune, start int) (string, int, error) {
	// Find the matching close bracket, handling nesting
	depth := 0

	i := start
	for i < len(runes) {
		switch runes[i] {
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				// We have the full character class from start to i (inclusive)
				content := runes[start : i+1]

				result, err := processCharClass(content)
				if err != nil {
					return "", 0, err
				}

				return result, i + 1 - start, nil
			}
		case '\\':
			i++ // skip next character
		}

		i++
	}
	// No closing bracket found — pass through as-is
	return string(runes[start : start+1]), 1, nil
}

// processCharClass processes a character class, expanding subtraction and
// translating embedded \p{} and \i/\c escapes.
func processCharClass(runes []rune) (string, error) {
	s := string(runes)
	if err := validateXPathCharClassStructure(s); err != nil {
		return "", err
	}

	if err := validateXPathCharClassSubtraction(s); err != nil {
		return "", err
	}
	// Preserve character class subtraction for the shared engine.
	// Class structure is preserved through translation and parsed by the engine.
	result, err := translateClassContent(s)
	if err != nil {
		return "", err
	}

	return result, nil
}

func validateXPathCharClassStructure(class string) error {
	runes := []rune(class)
	if len(runes) < 2 || runes[0] != '[' || runes[len(runes)-1] != ']' {
		return nil
	}

	first := 1
	if first < len(runes)-1 && runes[first] == '^' {
		first++
	}

	if first >= len(runes)-1 {
		return &regexError{
			Code:    lexicon.ErrFORX0002,
			Message: fmt.Sprintf("invalid character class: %s", class),
		}
	}

	prevRaw := rune(0)

	for i := first; i < len(runes)-1; {
		if runes[i] == '\\' {
			if i+1 >= len(runes)-1 {
				return &regexError{
					Code:    lexicon.ErrFORX0002,
					Message: fmt.Sprintf("invalid character class: %s", class),
				}
			}

			i += 2

			continue
		}

		if i == first && (runes[i] == ']' || runes[i] == '[') {
			return &regexError{
				Code:    lexicon.ErrFORX0002,
				Message: fmt.Sprintf("invalid character class: %s", class),
			}
		}

		if runes[i] == '[' && prevRaw != '-' {
			return &regexError{
				Code:    lexicon.ErrFORX0002,
				Message: fmt.Sprintf("invalid character class: %s", class),
			}
		}
		// An interior raw '-' denotes a range operator whose endpoints must be
		// single characters, never another '-'. A '-' is literal (not a range
		// operator) at the start of the class (i == first) or immediately
		// before the closing ']' (runes[i+1] == ']'); a '-' immediately before
		// '[' is the operator of a '-[' character-class subtraction (validated
		// separately by validateXPathCharClassSubtraction), not a range. An
		// interior, non-subtraction '-' whose immediately-preceding or
		// immediately-following raw char is itself a literal '-' uses a '-' as
		// a range endpoint, which the XSD/XPath regex grammar forbids — except
		// when that adjacent '-' is itself the operator of a '-[' subtraction
		// (its own following char is '['), which is a literal dash abutting the
		// subtraction operator (e.g. the valid base group of '[a--[b]]'), not a
		// range endpoint.
		if runes[i] == '-' && i != first && runes[i+1] != ']' && runes[i+1] != '[' {
			precededByHyphen := prevRaw == '-'

			followedByHyphen := runes[i+1] == '-' && (i+2 >= len(runes) || runes[i+2] != '[')
			if precededByHyphen || followedByHyphen {
				return &regexError{
					Code:    lexicon.ErrFORX0002,
					Message: fmt.Sprintf("invalid character class: %s", class),
				}
			}
		}

		prevRaw = runes[i]
		i++
	}

	return nil
}

func validateXPathCharClassSubtraction(class string) error {
	if !strings.Contains(class, "-[") {
		return nil
	}

	runes := []rune(class)
	if len(runes) < 4 || runes[0] != '[' || runes[len(runes)-1] != ']' {
		return nil
	}

	for i := 1; i < len(runes)-2; i++ {
		if runes[i] == '\\' {
			i++
			continue
		}

		if runes[i] == '-' && runes[i+1] == '[' {
			if i == 1 || (i == 2 && runes[1] == '^') {
				return &regexError{
					Code:    lexicon.ErrFORX0002,
					Message: fmt.Sprintf("invalid character class subtraction: %s", class),
				}
			}
		}
	}

	return nil
}

// translateClassContent translates \p{}, \i, \c escapes inside a character class.
func translateClassContent(s string) (string, error) {
	var b strings.Builder

	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		if runes[i] == '\\' && i+1 < len(runes) {
			replacement, consumed, err := translateClassEscape(runes, i)
			if err != nil {
				return "", err
			}

			if consumed > 0 {
				b.WriteString(replacement)

				i += consumed - 1

				continue
			}
		}

		b.WriteRune(runes[i])
	}

	return b.String(), nil
}

func translateClassEscape(runes []rune, start int) (string, int, error) {
	next := runes[start+1]
	if (next == 'p' || next == 'P') && start+2 < len(runes) && runes[start+2] == '{' {
		if end := findClosingBrace(runes, start+3); end >= 0 {
			replacement, err := translateUnicodeProperty(string(runes[start+3:end]), next == 'P')
			return replacement, end - start + 1, err
		}
	}

	switch next {
	case 'i':
		return xmlNameStartCharRange, 2, nil
	case 'I':
		return xmlNameStartCharRangeNeg, 2, nil
	case 'c':
		return xpathRegexNameCharRange, 2, nil
	case 'C':
		return xpathRegexNameCharRangeNeg, 2, nil
	case 'd':
		return `\p{Nd}`, 2, nil
	case 'D':
		return `\P{Nd}`, 2, nil
	case 'w':
		return `\p{L}\p{M}\p{N}\p{S}`, 2, nil
	case 'W':
		return `\p{P}\p{Z}\p{C}`, 2, nil
	default:
		return "", 0, nil
	}
}

func validateXPathRegex(pattern string, allowBackrefs bool) error {
	state := regexValidation{runes: []rune(pattern), allowBackrefs: allowBackrefs}
	for i := 0; i < len(state.runes); i++ {
		r := state.runes[i]
		if r == '\\' && i+1 < len(state.runes) {
			end, err := state.validateEscape(i)
			if err != nil {
				return err
			}

			i = end

			continue
		}

		switch r {
		case '[':
			state.inCharClass++
			continue
		case ']':
			if state.inCharClass == 0 {
				return &regexError{
					Code:    lexicon.ErrFORX0002,
					Message: "unescaped ']' outside character class is not allowed in XPath regex",
				}
			}

			state.inCharClass--

			continue
		}

		if state.inCharClass == 0 {
			if err := state.validateOutsideClass(i); err != nil {
				return err
			}
		}
	}

	if state.inCharClass > 0 {
		return &regexError{Code: lexicon.ErrFORX0002, Message: "unterminated character class in XPath regex"}
	}

	return nil
}

func hasXPathBackrefs(pattern string) bool {
	runes := []rune(pattern)
	inCharClass := 0

	for i := 0; i < len(runes)-1; i++ {
		switch runes[i] {
		case '[':
			inCharClass++
		case ']':
			if inCharClass > 0 {
				inCharClass--
			}
		case '\\':
			if inCharClass == 0 && runes[i+1] >= '1' && runes[i+1] <= '9' {
				return true
			}

			i++
		}
	}

	return false
}

func rejectPerlSpecific(pattern string) error {
	runes := []rune(pattern)
	for i := 0; i < len(runes); i++ {
		if runes[i] == '\\' && i+1 < len(runes) {
			switch runes[i+1] {
			case 'b', 'B', 'A', 'Z', 'z', 'x', 'u', 'U':
				return &regexError{
					Code:    lexicon.ErrFORX0002,
					Message: fmt.Sprintf("Perl-specific escape \\%c is not allowed in XPath regex", runes[i+1]),
				}
			}

			i++ // skip escaped character

			continue
		}
		// Reject inline flags (?...) — XPath uses flags parameter instead
		if runes[i] == '(' && i+1 < len(runes) && runes[i+1] == '?' {
			// Allow (?:...) for non-capturing groups
			if i+2 < len(runes) && runes[i+2] == ':' {
				continue
			}

			return &regexError{
				Code:    lexicon.ErrFORX0002,
				Message: "inline flag groups (?...) are not allowed in XPath regex",
			}
		}
	}

	return nil
}

type classRange struct {
	low  int64
	high int64
}

// ResolveProperty preserves Unicode block escapes as predicates, so the i flag
// cannot accidentally case-fold them after expansion into character ranges.
func ResolveProperty(name string) *unicode.RangeTable {
	if !strings.HasPrefix(name, "Is") {
		return nil
	}

	spec, ok := lookupUnicodeBlockRange(name[2:])
	if !ok {
		return nil
	}

	ranges, err := parseClassRanges(spec)
	if err != nil {
		return nil
	}

	table := &unicode.RangeTable{}

	for _, r := range ranges {
		if r.low <= 0xFFFF {
			table.R16 = append(table.R16, unicode.Range16{Lo: uint16(r.low), Hi: uint16(min(r.high, 0xFFFF)), Stride: 1})
		}

		if r.high > 0xFFFF {
			table.R32 = append(table.R32, unicode.Range32{Lo: uint32(max(r.low, 0x10000)), Hi: uint32(r.high), Stride: 1})
		}
	}

	return table
}

func parseClassRanges(spec string) ([]classRange, error) {
	runes := []rune(spec)

	var ranges []classRange

	for i := 0; i < len(runes); {
		low, next, err := parseClassRune(runes, i)
		if err != nil {
			return nil, err
		}

		i = next

		high := low
		if i < len(runes)-1 && runes[i] == '-' {
			high, i, err = parseClassRune(runes, i+1)
			if err != nil {
				return nil, err
			}
		}

		ranges = append(ranges, classRange{low: low, high: high})
	}

	return ranges, nil
}

func parseClassRune(runes []rune, start int) (int64, int, error) {
	if start >= len(runes) {
		return 0, start, fmt.Errorf("unexpected end of character class range")
	}

	if runes[start] != '\\' {
		return int64(runes[start]), start + 1, nil
	}

	if start+1 >= len(runes) {
		return 0, start, fmt.Errorf("dangling escape in character class range")
	}

	if runes[start+1] != 'x' {
		return int64(runes[start+1]), start + 2, nil
	}

	if start+2 >= len(runes) || runes[start+2] != '{' {
		return 0, start, fmt.Errorf("invalid hex escape in character class range")
	}

	end := -1

	for i := start + 3; i < len(runes); i++ {
		if runes[i] == '}' {
			end = i
			break
		}
	}

	if end < 0 {
		return 0, start, fmt.Errorf("unterminated hex escape in character class range")
	}

	value, err := strconv.ParseInt(string(runes[start+3:end]), 16, 64)
	if err != nil {
		return 0, start, err
	}

	return value, end + 1, nil
}

// regexError keeps this package layering-neutral (no xpath dependency).
// Callers map it back to their own error type; xpath wraps it as XPathError.
type regexError struct {
	Code    string
	Message string
	Cause   error
}

func (e *regexError) Error() string { return e.Message }

func (e *regexError) Unwrap() error { return e.Cause }

func findClosingBrace(runes []rune, start int) int {
	for i := start; i < len(runes); i++ {
		if runes[i] == '}' {
			return i
		}
	}

	return -1
}

func translateUnicodeProperty(name string, neg bool) (string, error) {
	prefix := `\p`
	if neg {
		prefix = `\P`
	}

	if strings.HasPrefix(name, "Is") {
		blockName := name[2:]
		if _, ok := lookupUnicodeBlockRange(blockName); ok {
			return prefix + "{" + name + "}", nil
		}

		return "", &regexError{Code: lexicon.ErrFORX0002, Message: fmt.Sprintf("unknown Unicode block: Is%s", blockName)}
	}

	if isGoSupportedProperty(name) {
		return prefix + "{" + name + "}", nil
	}

	return "", &regexError{Code: lexicon.ErrFORX0002, Message: fmt.Sprintf("unknown Unicode property: %s", name)}
}

func lookupUnicodeBlockRange(name string) (string, bool) {
	if name == "" {
		return "", false
	}

	return lookupUnicodeBlock(name)
}

// XML Schema category escapes use general categories, not Unicode scripts.
func isGoSupportedProperty(name string) bool {
	switch name {
	case "L", "Lu", "Ll", "Lt", "Lm", "Lo", "M", "Mn", "Mc", "Me",
		"N", "Nd", "Nl", "No", "P", "Pc", "Pd", "Ps", "Pe", "Pi", "Pf", "Po",
		"Z", "Zs", "Zl", "Zp", "S", "Sm", "Sc", "Sk", "So", "C", "Cc", "Cf", "Co", "Cn":
		return true
	default:
		return false
	}
}

func lookupUnicodeBlock(name string) (string, bool) {
	ranges, ok := unicodeBlocks[name]
	return ranges, ok
}

// validateXPathRegex checks for patterns that Go's regexp accepts but
// the XPath/XML Schema regex spec forbids. This must be called before
// compilation to reject invalid patterns with FORX0002.
type regexValidation struct {
	runes         []rune
	groupStack    []int
	inCharClass   int
	captureCount  int
	inQuantifier  bool
	allowBackrefs bool
}

// validateEscape returns the final consumed rune's index.
func (v *regexValidation) validateEscape(start int) (int, error) {
	next := v.runes[start+1]
	if next == '0' {
		return 0, &regexError{Code: lexicon.ErrFORX0002, Message: "back-reference \\0 is not allowed in XPath regex"}
	}

	if v.inCharClass == 0 && next >= '1' && next <= '9' {
		return v.validateBackreference(start)
	}

	if (next == 'p' || next == 'P') && start+2 < len(v.runes) && v.runes[start+2] == '{' {
		end := findClosingBrace(v.runes, start+3)
		if end < 0 {
			return 0, &regexError{
				Code:    lexicon.ErrFORX0002,
				Message: fmt.Sprintf("unterminated \\%c{ in regex", next),
			}
		}

		_, err := translateUnicodeProperty(string(v.runes[start+3:end]), next == 'P')

		return end, err
	}

	return start + 1, nil
}

func (v *regexValidation) validateBackreference(start int) (int, error) {
	ref, validEnd, end, invalid := resolveXPathBackref(v.runes, start+1, v.captureCount, v.groupStack)
	if !v.allowBackrefs {
		return 0, &regexError{
			Code:    lexicon.ErrFORX0002,
			Message: fmt.Sprintf("back-reference \\%d is not allowed in XPath regex", ref),
		}
	}

	if invalid || validEnd < 0 {
		return 0, &regexError{
			Code:    lexicon.ErrFORX0002,
			Message: fmt.Sprintf("invalid back-reference \\%s in XPath regex", string(v.runes[start+1:end])),
		}
	}

	return end - 1, nil
}

func (v *regexValidation) validateOutsideClass(index int) error {
	switch v.runes[index] {
	case '(':
		if index+2 < len(v.runes) && v.runes[index+1] == '?' && v.runes[index+2] == ':' {
			v.groupStack = append(v.groupStack, 0)
			return nil
		}

		v.captureCount++
		v.groupStack = append(v.groupStack, v.captureCount)
	case ')':
		if len(v.groupStack) > 0 {
			v.groupStack = v.groupStack[:len(v.groupStack)-1]
		}
	case '{':
		if !isValidQuantifierBrace(v.runes, index) {
			return &regexError{
				Code:    lexicon.ErrFORX0002,
				Message: "unescaped '{' outside quantifier is not allowed in XPath regex",
			}
		}

		v.inQuantifier = true
	case '}':
		if !v.inQuantifier {
			return &regexError{
				Code:    lexicon.ErrFORX0002,
				Message: "unescaped '}' outside quantifier is not allowed in XPath regex",
			}
		}

		v.inQuantifier = false
	}

	return nil
}

func isOpenCaptureGroup(groupStack []int, ref int) bool {
	return slices.Contains(groupStack, ref)
}

func resolveXPathBackref(runes []rune, start, captureCount int, groupStack []int) (int, int, int, bool) {
	ref := 0
	validEnd := -1
	end := start

	value := 0
	for end < len(runes) && runes[end] >= '0' && runes[end] <= '9' {
		// Stop accumulating once value exceeds captureCount: more digits only
		// grow it, and a long digit run would wrap int (past 2^31-1 where int
		// is 32 bits) back into the capture range.
		if value <= captureCount {
			value = value*10 + int(runes[end]-'0')
		}

		end++
	}

	if value > 0 && value <= captureCount {
		if isOpenCaptureGroup(groupStack, value) {
			return 0, -1, end, true
		}

		return value, end, end, false
	}

	value = 0
	for i := start; i < end; i++ {
		if value > captureCount {
			break
		}

		value = value*10 + int(runes[i]-'0')
		if value > 0 && value <= captureCount && !isOpenCaptureGroup(groupStack, value) {
			ref = value
			validEnd = i + 1
		}
	}

	return ref, validEnd, end, false
}

// validQuantifierContent recognizes digits [ "," [ digits ] ].
func validQuantifierContent(s string) bool {
	left, right, comma := strings.Cut(s, ",")
	if left == "" {
		return false
	}

	for i := range len(left) {
		if left[i] < '0' || left[i] > '9' {
			return false
		}
	}

	if comma {
		for i := range len(right) {
			if right[i] < '0' || right[i] > '9' {
				return false
			}
		}
	}

	return true
}

// isValidQuantifierBrace checks whether '{' at position i is part of a
// valid quantifier {n}, {n,}, or {n,m}. The '{' must be preceded by a
// quantifiable atom (not at the start) and its content must match the
// quantifier pattern.
func isValidQuantifierBrace(runes []rune, i int) bool {
	// Must have a preceding quantifiable atom
	if i == 0 {
		return false
	}

	prev := runes[i-1]
	// Valid preceding chars for a quantifier: ), ], or any non-meta char,
	// or an escape sequence. We check broadly.
	if prev == '|' || prev == '(' || prev == '{' {
		return false
	}

	end := -1

	for j := i + 1; j < len(runes); j++ {
		if runes[j] == '}' {
			end = j
			break
		}
	}

	if end < 0 {
		return false
	}

	content := string(runes[i+1 : end])

	return validQuantifierContent(content)
}
