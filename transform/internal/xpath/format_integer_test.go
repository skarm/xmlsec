package xpath //nolint:testpackage // Exercises picture formatting on both evaluation paths.

import (
	"errors"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestFnFormatIntegerPicturesASTAndVM(t *testing.T) {
	t.Parallel()
	assertFunctionResults(t, []functionResultCase{
		{"decimal grouping and negative padding", `(format-integer(12345678,'#,##0'),format-integer(-42,'0000'))`, "12,345,678|-0042"},
		{"alphabetic numbering carries across alphabet", `(format-integer(26,'A'),format-integer(27,'A'),format-integer(52,'a'),format-integer(53,'a'),format-integer(25,'α'))`, "Z|AA|az|ba|αα"},
		{"alphabetic numbering retains large integers and signs", `(format-integer(0,'A'),format-integer(-27,'a'),format-integer(9223372036854775807,'A'),format-integer(123456789012345678901234567890,'a'))`, "0|-aa|CRPXNLSKVLJFHG|feavzaanahwhnblunnvxz"},
		{"roman numbers subtract around thresholds", `(format-integer(4,'i'),format-integer(49,'I'),format-integer(944,'I'),format-integer(0,'I'))`, "iv|XLIX|CMXLIV|0"},
		{"non-ASCII numbering pictures", `(format-integer(12,'٠٠٠'),format-integer(20,'①'),format-integer(21,'①'),format-integer(12,'⑴'),format-integer(3,'⒈'),format-integer(12,'一'))`, "٠١٢|⑳|21|⑿|⒊|十二"},
		{"English ordinal exceptions", `(format-integer(1,'1;o','en'),format-integer(12,'1;o','en'),format-integer(23,'1;o','en'),format-integer(111,'1;o','en'))`, "1st|12th|23rd|111th"},
		{"number words in multiple languages", `(format-integer(12,'w','en'),format-integer(20,'W','en'),format-integer(21,'w','fr'),format-integer(21,'w','de'),format-integer(28,'w','it'))`, "twelve|TWENTY|vingt et un|einundzwanzig|ventotto"},
		{"alphabetic modifier with optional numbering mode", `(format-integer(27,'a;a','en'),format-integer(27,'001;ca','en'),format-integer(27,'1;oa','en'),format-integer(1234,'#;##0;a','en'))`, "aa|027|27th|1;234"},
		{"modifier variants and omitted suffix", `(format-integer(27,'1;o()t','en'),format-integer(27,'1;o(foo(bar))','en'),format-integer(27,'001;','en'))`, "27th|27th|027"},
	})
}

func TestFnFormatIntegerOrdinalWordsASTAndVM(t *testing.T) {
	t.Parallel()
	assertFunctionResults(t, []functionResultCase{
		{"english irregular and tens ordinals", `(format-integer(12,'w;o','en'),format-integer(20,'W;o','en'),format-integer(21,'Ww;o','en'),format-integer(100,'w;o','en'))`, "twelfth|TWENTIETH|Twenty First|one hundredth"},
		{"german irregular and regular ordinals", `(format-integer(3,'w;o','de'),format-integer(4,'w;o','de'),format-integer(20,'Ww;o','de'))`, "dritte|vierte|Zwanzigste"},
		{"french ordinals", `(format-integer(1,'Ww;o','fr'), format-integer(12,'w;o','fr'))`, "Premier|douzième"},
		{"italian gender and irregular ordinals", `(format-integer(1,'w;o','it'),format-integer(2,'w;o(-a)','it'),format-integer(8,'W;o','it'),format-integer(11,'w;o','it'))`, "primo|seconda|OTTAVO|undicesimo"},
	})
}

func TestFnFormatIntegerGroupingAndCardinalsASTAndVM(t *testing.T) {
	t.Parallel()
	assertFunctionResults(t, []functionResultCase{
		{"irregular grouping uses explicit offsets", `(format-integer(12345678,'##.##,000'),format-integer(1234,'##.##,000'),format-integer(12,'00,000'))`, "123.45,678|1,234|00,012"},
		{"mixed separators keep their positions", `format-integer(12345678901,'000.000,000')`, "12345.678,901"},
		{"regular grouping repeats across a partial left group", `(format-integer(12345678901,'##0,000,000'),format-integer(12345678901,'#0,000,000'),format-integer(12345678901,'##,000,000'))`, "12,345,678,901|12,345,678,901|12,345,678,901"},
		{"wide left groups do not repeat", `(format-integer(12345678901,'0000,000'),format-integer(12345678901,'0000,000,000'))`, "12345678,901|12345,678,901"},
		{"regular grouping preserves Unicode digits and separators", `format-integer(12345678901,'٠٬٠٠٠٬٠٠٠')`, "١٢٬٣٤٥٬٦٧٨٬٩٠١"},
		{"tokens without mandatory digits fall back", `(format-integer(12345678901,'#'),format-integer(12345678901,'#a'),format-integer(12345678901,'##,###'))`, "12345678901|12345678901|12345678901"},
		{"integer larger than int64 retains all digits", `format-integer(123456789012345678901234567890,'#,##0')`, "123,456,789,012,345,678,901,234,567,890"},
		{"german combines thousands and hundreds", `(format-integer(0,'w','de'),format-integer(-1024,'w','de'),format-integer(2000101,'w','de'))`, "null|-eintausendvierundzwanzig|zwei millionen einhunderteins"},
		{"french joins composite tens and hundreds", `(format-integer(71,'w','fr'),format-integer(80,'w','fr'),format-integer(91,'w','fr'),format-integer(200,'w','fr'),format-integer(1201,'w','fr'))`, "soixante et onze|quatre-vingts|quatre-vingt-onze|deux cents|mille deux cent un"},
		{"italian elision and plural thousands", `(format-integer(21,'w','it'),format-integer(30,'w','it'),format-integer(-2102,'w','it'))`, "ventuno|trenta|-duemilacentodue"},
		{"unknown language falls back to default", `format-integer(42,'w','zz')`, "forty two"},
	})
}

func TestFnFormatIntegerRejectsInvalidPicturesASTAndVM(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ name, expression string }{
		{"mixed digit families", `format-integer(1234,'0٠0')`},
		{"ASCII letter", `format-integer(1234,'0A0')`},
		{"Unicode letter", `format-integer(1234,'0Ж0')`},
		{"Unicode non-decimal number", `format-integer(1234,'0①0')`},
		{"duplicate ordinal modifier", `format-integer(27,'1;oo')`},
		{"reordered modifier flags", `format-integer(27,'1;to')`},
		{"duplicate traditional modifier", `format-integer(27,'1;ctt')`},
		{"variant without numbering mode", `format-integer(27,'1;(variant)')`},
		{"variant after traditional modifier", `format-integer(27,'1;t(variant)')`},
		{"competing alphabetic and traditional modifiers", `format-integer(27,'1;at')`},
	} {
		for _, mode := range []string{runtimeASTMode, "VM"} {
			t.Run(test.name+"/"+mode, func(t *testing.T) {
				t.Parallel()
				seq, err := evaluateFunctionExpression(t, test.expression, mode)
				if xdm.SequenceLen(seq) != 0 || !errors.Is(err, &xdm.Error{Code: "FODF1310"}) {
					t.Fatalf("%s = (%v, %v); want no result and FODF1310", test.expression, seq, err)
				}
			})
		}
	}
}
