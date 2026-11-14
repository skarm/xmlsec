package xpath //nolint:testpackage // Exercises picture formatting on both evaluation paths.

import "testing"

func TestFnFormatIntegerPicturesASTAndVM(t *testing.T) {
	t.Parallel()
	assertFunctionResults(t, []functionResultCase{
		{"decimal grouping and negative padding", `(format-integer(12345678,'#,##0'),format-integer(-42,'0000'))`, "12,345,678|-0042"},
		{"alphabetic numbering carries across alphabet", `(format-integer(26,'A'),format-integer(27,'A'),format-integer(52,'a'),format-integer(53,'a'),format-integer(25,'α'))`, "Z|AA|az|ba|αα"},
		{"roman numbers subtract around thresholds", `(format-integer(4,'i'),format-integer(49,'I'),format-integer(944,'I'),format-integer(0,'I'))`, "iv|XLIX|CMXLIV|0"},
		{"non-ASCII numbering pictures", `(format-integer(12,'٠٠٠'),format-integer(20,'①'),format-integer(21,'①'),format-integer(12,'⑴'),format-integer(3,'⒈'),format-integer(12,'一'))`, "٠١٢|⑳|21|⑿|⒊|十二"},
		{"English ordinal exceptions", `(format-integer(1,'1;o','en'),format-integer(12,'1;o','en'),format-integer(23,'1;o','en'),format-integer(111,'1;o','en'))`, "1st|12th|23rd|111th"},
		{"number words in multiple languages", `(format-integer(12,'w','en'),format-integer(20,'W','en'),format-integer(21,'w','fr'),format-integer(21,'w','de'),format-integer(28,'w','it'))`, "twelve|TWENTY|vingt et un|einundzwanzig|ventotto"},
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
		{"integer larger than int64 retains all digits", `format-integer(123456789012345678901234567890,'#,##0')`, "123,456,789,012,345,678,901,234,567,890"},
		{"german combines thousands and hundreds", `(format-integer(0,'w','de'),format-integer(-1024,'w','de'),format-integer(2000101,'w','de'))`, "null|-eintausendvierundzwanzig|zwei millionen einhunderteins"},
		{"french joins composite tens and hundreds", `(format-integer(71,'w','fr'),format-integer(80,'w','fr'),format-integer(91,'w','fr'),format-integer(200,'w','fr'),format-integer(1201,'w','fr'))`, "soixante et onze|quatre-vingts|quatre-vingt-onze|deux cents|mille deux cent un"},
		{"italian elision and plural thousands", `(format-integer(21,'w','it'),format-integer(30,'w','it'),format-integer(-2102,'w','it'))`, "ventuno|trenta|-duemilacentodue"},
		{"unknown language falls back to default", `format-integer(42,'w','zz')`, "forty two"},
	})
}
