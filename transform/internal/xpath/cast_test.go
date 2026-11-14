package xpath //nolint:testpackage // Exercises atomic casts on both evaluation paths.

import (
	"errors"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestAtomicConversionsASTAndVM(t *testing.T) {
	t.Parallel()
	assertFunctionResults(t, []functionResultCase{
		{"narrow signed integer bounds", `(xs:byte('-128'),xs:short('32767'),xs:int('-2147483648'),xs:long('9223372036854775807'))`, "-128|32767|-2147483648|9223372036854775807"},
		{"unsigned long goes beyond signed range", `(xs:unsignedByte(255),xs:unsignedShort(65535),xs:unsignedInt(4294967295),xs:unsignedLong('18446744073709551615'))`, "255|65535|4294967295|18446744073709551615"},
		{"signed derived ranges include the right endpoint", `(0 castable as xs:nonNegativeInteger,0 castable as xs:negativeInteger,0 castable as xs:nonPositiveInteger,0 castable as xs:positiveInteger,256 castable as xs:unsignedByte,(-129) castable as xs:byte)`, "true|false|true|false|false|false"},
		{"numeric conversions truncate toward zero", `(xs:byte(-3.75),xs:short(3.75),xs:integer(true()),xs:boolean(0),xs:boolean(-1))`, "-3|3|1|false|true"},
		{"Gregorian types retain their lexical forms", `(xs:gYear('2024Z'),xs:gYearMonth('2024-02+01:00'),xs:gMonth('--02'),xs:gMonthDay('--02-29'),xs:gDay('---29'))`, "2024Z|2024-02+01:00|--02|--02-29|---29"},
		{"binary encodings preserve octets", `(xs:base64Binary(xs:hexBinary('00ff')),xs:hexBinary(xs:base64Binary('AP8=')), '0g' castable as xs:hexBinary)`, "AP8=|00FF|false"},
		{"calendar projections retain timezone", `let $dt := xs:dateTime('2024-02-29T23:04:05+02:00') return (xs:date($dt),xs:time($dt),xs:dateTime(xs:date($dt)),xs:dateTimeStamp($dt) instance of xs:dateTimeStamp)`, "2024-02-29+02:00|23:04:05+02:00|2024-02-29T00:00:00+02:00|true"},
		{"string restrictions preserve significant whitespace rules", `(xs:normalizedString(codepoints-to-string((97,9,98,10,99))),xs:token(' a  b '),xs:language('en-GB'),xs:NCName('item-1'),count(xs:NMTOKENS('one two')))`, "a b c|a b|en-GB|item-1|2"},
	})
}

func TestCastAtomicErrorsASTAndVM(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ name, expression, code string }{
		{"unsigned overflow", `xs:unsignedLong('18446744073709551616')`, "FORG0001"},
		{"dateTimeStamp requires timezone", `xs:dateTime('2024-02-29T12:00:00') cast as xs:dateTimeStamp`, "FORG0001"},
	} {
		for _, mode := range []string{runtimeASTMode, "VM"} {
			t.Run(test.name+"/"+mode, func(t *testing.T) {
				t.Parallel()
				seq, err := evaluateFunctionExpression(t, test.expression, mode)
				if xdm.SequenceLen(seq) != 0 || !errors.Is(err, &xdm.Error{Code: test.code}) {
					t.Fatalf("%s = %v, %v; want no result and %s", test.expression, seq, err, test.code)
				}
			})
		}
	}
}
