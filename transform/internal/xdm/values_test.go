package xdm_test

import (
	"context"
	"errors"
	"math"
	"math/big"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestArrayFlattenEmptyMembers(t *testing.T) {
	t.Parallel()

	a := xdm.NewArray([]xdm.Sequence{nil, xdm.SingleString("before"), xdm.ItemSlice{xdm.NewArrayFromImmutableMembers([]xdm.Sequence{nil, xdm.SingleString("inside")})}, nil})
	assertStringItems(t, a.Flatten(), "before", "inside")
	assertStringItems(t, xdm.NewArray([]xdm.Sequence{nil}).Flatten())
}

func TestArrayFlattenDeepOrderAndOwnership(t *testing.T) {
	t.Parallel()
	const depth = 4096
	leaf := big.NewInt(7)
	array := xdm.NewArray([]xdm.Sequence{xdm.SingleIntegerBig(leaf)})
	for i := range depth {
		array = xdm.NewArrayFromImmutableMembers([]xdm.Sequence{nil, xdm.SingleInteger(int64(i)), xdm.ItemSlice{array}, nil})
	}
	result := array.Flatten()
	if result.Len() != depth+1 {
		t.Fatal("flattened size", result.Len())
	}
	for i := range depth {
		if got := result.Get(i).(xdm.AtomicValue).IntegerVal(); got != int64(depth-i-1) {
			t.Fatal("nested array changed order", i, got)
		}
	}
	result.Get(depth).(xdm.AtomicValue).BigInt().SetInt64(99)
	if got := array.Flatten().Get(depth).(xdm.AtomicValue).IntegerVal(); got != 7 {
		t.Fatal("flatten exposed mutable leaf", got)
	}
}

func TestArrayPersistentUpdatesAndBounds(t *testing.T) {
	t.Parallel()

	payload := big.NewInt(7)
	member := xdm.ItemSlice{xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: payload}}
	original := xdm.NewArray([]xdm.Sequence{member, nil, xdm.SingleString("tail")})
	payload.SetInt64(99)
	member[0] = stringKey("replaced")
	got, err := original.Get(1)
	if err != nil || got.Get(0).(xdm.AtomicValue).BigInt().Int64() != 7 {
		t.Fatalf("array retained caller payload: %v, %v", got, err)
	}
	got.Get(0).(xdm.AtomicValue).BigInt().SetInt64(100)
	got, err = original.Get(1)
	if err != nil || got.Get(0).(xdm.AtomicValue).BigInt().Int64() != 7 {
		t.Fatal("Get exposed array payload")
	}
	members := original.Members()
	members[0].Get(0).(xdm.AtomicValue).BigInt().SetInt64(101)
	members[2] = nil
	view, err := original.GetView(1)
	if err != nil {
		t.Fatalf("array.GetView(1): %v", err)
	}
	if view.Get(0).(xdm.AtomicValue).BigInt().Int64() != 7 {
		t.Fatal("Members exposed array payload")
	}
	tail := requireArrayMember(t, original, 3)
	assertStringItems(t, tail, "tail")
	replacement := xdm.ItemSlice{stringKey("changed")}
	updated, err := original.Put(2, replacement)
	if err != nil {
		t.Fatal(err)
	}
	replacement[0] = stringKey("mutated")
	seq := requireArrayMember(t, updated, 2)
	assertStringItems(t, seq, "changed")
	seq = requireArrayMember(t, original, 2)
	assertStringItems(t, seq)
	appended := updated.Append(xdm.SingleString("new"))
	if original.Size() != 3 || updated.Size() != 3 || appended.Size() != 4 {
		t.Fatal("persistent update changed source size")
	}
	seq = requireArrayMember(t, appended, 4)
	assertStringItems(t, seq, "new")
	sub, err := appended.SubArray(2, 2)
	if err != nil {
		t.Fatal(err)
	}
	assertStringItems(t, sub.Flatten(), "changed", "tail")
	empty, err := original.SubArray(4, 0)
	if err != nil || empty.Size() != 0 {
		t.Fatalf("empty trailing subarray: %v, %v", empty, err)
	}
	for _, index := range []int{0, -1, 4, math.MaxInt} {
		_, err = original.Get(index)
		requireXDMCode(t, err, "FOAY0001")
		_, err = original.GetView(index)
		requireXDMCode(t, err, "FOAY0001")
		_, err = original.Put(index, nil)
		requireXDMCode(t, err, "FOAY0001")
	}
	for _, bounds := range [][2]int{{0, 0}, {5, 0}, {2, 3}, {1, math.MaxInt}, {math.MaxInt, 1}} {
		_, err = original.SubArray(bounds[0], bounds[1])
		requireXDMCode(t, err, "FOAY0001")
	}
	_, err = original.SubArray(1, -1)
	requireXDMCode(t, err, "FOAY0002")
}

func TestArrayErrorsKeepQualifiedCodes(t *testing.T) {
	t.Parallel()

	_, err := (xdm.ArrayItem{}).Get(1)

	var coded *xdm.Error
	if !errors.As(err, &coded) || coded.Code != "FOAY0001" || coded.CodeQName().Local != "FOAY0001" {
		t.Fatalf("lost structured array error: %v", err)
	}
}

// Each level contributes a value, as in recursively generated array-valued
// expressions. Immutable construction is excluded from the measured flatten.
func BenchmarkArrayFlattenNested(b *testing.B) {
	for _, depth := range []int{1, 32, 256} {
		b.Run(strconv.Itoa(depth), func(b *testing.B) {
			array := xdm.NewArrayFromImmutableMembers(nil)
			for i := range depth {
				array = xdm.NewArrayFromImmutableMembers([]xdm.Sequence{xdm.SingleInteger(int64(i)), xdm.ItemSlice{array}})
			}
			b.ReportAllocs()
			for b.Loop() {
				if result := array.Flatten(); result.Len() != depth {
					b.Fatal("wrong flattened size")
				}
			}
		})
	}
}

func TestNumericConversionsRespectPrecisionAndBaseType(t *testing.T) {
	t.Parallel()

	for _, value := range []any{float64(16777217), float32(16777216), xdm.NewDouble(16777217)} {
		a := xdm.AtomicValue{TypeName: "Q{u}float", BaseType: xdm.TypeFloat, Value: value}
		if a.ToFloat64() != 16777216 || a.DoubleVal() != 16777216 || a.FloatVal().Float64() != 16777216 || a.FloatVal().Precision() != xdm.PrecisionFloat {
			t.Fatalf("float narrowing failed for %T", value)
		}
	}
	for _, value := range []any{float64(16777217), xdm.NewDouble(16777217)} {
		a := xdm.AtomicValue{TypeName: "Q{u}double", BaseType: xdm.TypeDouble, Value: value}
		if a.ToFloat64() != 16777217 || a.FloatVal().Float64() != 16777217 || a.FloatVal().Precision() != xdm.PrecisionDouble {
			t.Fatalf("double incorrectly narrowed for %T", value)
		}
	}
	for _, a := range []xdm.AtomicValue{{TypeName: xdm.TypeInteger, Value: int64(25)}, {TypeName: "Q{u}integer", BaseType: xdm.TypeLong, Value: big.NewInt(25)}, {TypeName: "Q{u}decimal", BaseType: xdm.TypeDecimal, Value: big.NewRat(25, 1)}} {
		if !a.IsNumeric() || a.ToFloat64() != 25 {
			t.Fatalf("numeric conversion: %v", a)
		}
	}

	decimal := xdm.AtomicValue{TypeName: "Q{u}decimal", BaseType: xdm.TypeDecimal, Value: big.NewRat(-1, 8)}
	if decimal.ToFloat64() != -0.125 {
		t.Fatal("decimal conversion discarded fractional magnitude/sign")
	}

	a := xdm.AtomicValue{TypeName: xdm.TypeInteger, BaseType: xdm.TypeFloat, Value: int64(16777217)}
	if a.ToFloat64() != 16777217 {
		t.Fatal("builtin numeric type did not take precedence over BaseType")
	}
	for _, value := range []any{int64(math.MinInt64), big.NewInt(math.MaxInt64)} {
		a := xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: value}
		n, ok := a.Int64Val()
		if !ok || n != a.IntegerVal() {
			t.Fatalf("in-range Int64Val: %d,%v", n, ok)
		}
	}
	over := new(big.Int).Lsh(big.NewInt(1), 63)
	if n, ok := (xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: over}).Int64Val(); ok || n != 0 {
		t.Fatalf("overflow Int64Val: %d,%v", n, ok)
	}
	if n, ok := (xdm.AtomicValue{TypeName: xdm.TypeString, Value: "1"}).Int64Val(); ok || n != 0 {
		t.Fatalf("string Int64Val: %d,%v", n, ok)
	}
	if (xdm.AtomicValue{Value: "123456789012345678901234567890"}).BigInt().String() != "123456789012345678901234567890" || (xdm.AtomicValue{Value: int64(-7)}).BigInt().Int64() != -7 {
		t.Fatal("BigInt parse/promotion")
	}
	if (xdm.AtomicValue{Value: "3/7"}).BigRat().Cmp(big.NewRat(3, 7)) != 0 {
		t.Fatal("BigRat rational parsing")
	}
	for _, value := range []any{"invalid", true} {
		if (xdm.AtomicValue{Value: value}).BigInt().Sign() != 0 || (xdm.AtomicValue{Value: value}).BigRat().Sign() != 0 {
			t.Fatal("invalid numeric input must return zero")
		}
	}
	if !(xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: xdm.NewDouble(math.NaN())}).IsNaN() || (xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: xdm.NewDouble(1)}).IsNaN() || (xdm.AtomicValue{TypeName: xdm.TypeString, Value: "NaN"}).IsNaN() {
		t.Fatal("atomic NaN classification")
	}
	if (xdm.AtomicValue{TypeName: xdm.TypeString, Value: "5"}).IsNumeric() {
		t.Fatal("numeric-looking string classified numeric")
	}
}

func TestAtomicCloningDetachesMutablePayloads(t *testing.T) {
	t.Parallel()

	integer := big.NewInt(7)
	rational := big.NewRat(3, 4)
	binary := []byte{1, 2}
	fraction, total := big.NewRat(1, 4), big.NewRat(5, 4)
	duration := xdm.Duration{Seconds: 1.25, FracSec: fraction, SecRat: total}
	original := xdm.ItemSlice{xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: integer}, xdm.AtomicValue{TypeName: xdm.TypeDecimal, Value: rational}, xdm.AtomicValue{TypeName: xdm.TypeHexBinary, Value: binary}, xdm.AtomicValue{TypeName: xdm.TypeDuration, Value: duration}, xdm.AtomicValue{TypeName: xdm.TypeDuration, Value: &duration}}
	clone := xdm.CloneSequence(original)
	integer.SetInt64(99)
	rational.SetInt64(99)
	binary[0] = 99
	fraction.SetInt64(99)
	total.SetInt64(99)
	if clone.Get(0).(xdm.AtomicValue).BigInt().Int64() != 7 || clone.Get(1).(xdm.AtomicValue).BigRat().Cmp(big.NewRat(3, 4)) != 0 || !reflect.DeepEqual(clone.Get(2).(xdm.AtomicValue).BytesVal(), []byte{1, 2}) {
		t.Fatal("atomic numeric/binary clone aliases input")
	}
	for _, i := range []int{3, 4} {
		value := clone.Get(i).(xdm.AtomicValue).Value
		var d xdm.Duration
		if v, ok := value.(xdm.Duration); ok {
			d = v
		} else {
			d = *value.(*xdm.Duration)
		}
		if d.FracSec.Cmp(big.NewRat(1, 4)) != 0 || d.SecRat.Cmp(big.NewRat(5, 4)) != 0 {
			t.Fatal("duration clone aliases rational fields")
		}
	}
	// A flattened leaf must also be detached from the array's immutable storage.
	a := xdm.NewArray([]xdm.Sequence{clone})
	flattened := a.Flatten()
	flattened.Get(0).(xdm.AtomicValue).BigInt().SetInt64(500)
	member := requireArrayMember(t, a, 1)
	if member.Get(0).(xdm.AtomicValue).BigInt().Int64() != 7 {
		t.Fatal("flattened atomic mutated original array")
	}
}

func TestDurationExactSeconds(t *testing.T) {
	t.Parallel()

	cases := []struct {
		d    xdm.Duration
		ym   bool
		want string
	}{
		{xdm.Duration{Months: 25, Seconds: 100, Negative: true}, true, "-25"},
		{xdm.Duration{Seconds: 1.5, FracSec: big.NewRat(1, 2)}, false, "3/2"},
		{xdm.Duration{Seconds: 1, FracSec: new(big.Rat).SetFrac(big.NewInt(999999999999999999), big.NewInt(1000000000000000000))}, false, "999999999999999999/1000000000000000000"},
		{xdm.Duration{Seconds: 9007199254740992, SecRat: new(big.Rat).SetInt(new(big.Int).SetUint64(9007199254740993)), Negative: true}, false, "-9007199254740993"},
		{xdm.Duration{Seconds: 2.5, Negative: true}, false, "-5/2"},
		{xdm.Duration{Negative: true}, false, "0"},
	}
	for _, tc := range cases {
		want, ok := new(big.Rat).SetString(tc.want)
		if !ok {
			t.Fatal("bad fixture")
		}
		var originalSeconds, originalFraction *big.Rat
		if tc.d.SecRat != nil {
			originalSeconds = new(big.Rat).Set(tc.d.SecRat)
		}
		if tc.d.FracSec != nil {
			originalFraction = new(big.Rat).Set(tc.d.FracSec)
		}
		got := xdm.DurationToRat(tc.d, tc.ym)
		if got.Cmp(want) != 0 {
			t.Fatalf("duration %+v YM%v: %s; want %s", tc.d, tc.ym, got, want)
		}
		got.SetInt64(999)
		if originalSeconds != nil && tc.d.SecRat.Cmp(originalSeconds) != 0 {
			t.Fatal("conversion result aliases source seconds")
		}
		if originalFraction != nil && tc.d.FracSec.Cmp(originalFraction) != 0 {
			t.Fatal("conversion result aliases source fraction")
		}
	}
}

func TestDecimalRendering(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		value *big.Rat
		want  string
	}{{big.NewRat(0, 1), "0"}, {big.NewRat(-10, 1), "-10"}, {big.NewRat(1, 8), "0.125"}, {big.NewRat(-1, 200), "-0.005"}, {big.NewRat(1, 3), "0.33333333333333333333"}} {
		if got := xdm.DecimalToString(tc.value); got != tc.want {
			t.Fatalf("decimal %s rendered %q; want %q", tc.value, got, tc.want)
		}
	}
}

func TestSchemaTypePromotionAndAncestry(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		value any
		want  string
	}{{int64(1), xdm.TypeInteger}, {big.NewInt(1), xdm.TypeInteger}, {big.NewRat(1, 2), xdm.TypeDecimal}, {xdm.NewDouble(1), xdm.TypeDouble}, {float64(1), xdm.TypeDouble}, {true, xdm.TypeBoolean}, {"s", xdm.TypeString}, {time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), xdm.TypeDateTime}, {xdm.Duration{}, xdm.TypeDuration}, {[]byte{1}, xdm.TypeBase64Binary}, {xdm.QNameValue{Local: "n"}, xdm.TypeQName}} {
		got := xdm.PromoteSchemaType(xdm.AtomicValue{TypeName: "Q{u}custom", Value: tc.value})
		if got.TypeName != tc.want || !reflect.DeepEqual(got.Value, tc.value) {
			t.Fatalf("promotion for %T: %v", tc.value, got)
		}
	}
	builtin := xdm.AtomicValue{TypeName: xdm.TypeDate, BaseType: xdm.TypeString, Value: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)}
	if !reflect.DeepEqual(xdm.PromoteSchemaType(builtin), builtin) {
		t.Fatal("builtin type changed by promotion")
	}
	custom := xdm.AtomicValue{TypeName: "Q{u}date", BaseType: xdm.TypeDate, Value: builtin.Value}
	if xdm.PromoteSchemaType(custom).TypeName != xdm.TypeDate || !xdm.IsAtomicSubtypeOf(custom, xdm.TypeAnyAtomicType) || xdm.IsAtomicSubtypeOf(custom, xdm.TypeDateTime) {
		t.Fatal("custom date's base type not respected")
	}
	unknown := xdm.AtomicValue{TypeName: "Q{u}unknown", Value: struct{}{}}
	if !reflect.DeepEqual(xdm.PromoteSchemaType(unknown), unknown) || xdm.IsAtomicSubtypeOf(unknown, xdm.TypeString) {
		t.Fatal("unknown type inferred without valid backing")
	}
	if xdm.IsAtomicSubtypeOf(xdm.AtomicValue{TypeName: xdm.TypeDateTime, Value: builtin.Value}, xdm.TypeDate) {
		t.Fatal("sibling date/dateTime types conflated")
	}
	for _, tc := range [][2]string{{xdm.TypeByte, xdm.TypeInteger}, {xdm.TypeUnsignedByte, xdm.TypeDecimal}, {xdm.TypePositiveInteger, xdm.TypeNumeric}, {xdm.TypeNegativeInteger, xdm.TypeDecimal}, {xdm.TypeID, xdm.TypeString}, {xdm.TypeENTITY, xdm.TypeToken}, {xdm.TypeDateTimeStamp, xdm.TypeDateTime}, {xdm.TypeDayTimeDuration, xdm.TypeDuration}} {
		if !xdm.IsSubtypeOf(tc[0], tc[1]) || !xdm.BuiltinIsSubtypeOf(tc[0], tc[1]) || xdm.IsSubtypeOf(tc[1], tc[0]) {
			t.Fatalf("subtype direction: %v", tc)
		}
	}
	if !xdm.IsSubtypeOf(xdm.TypeDouble, xdm.TypeNumeric) || !xdm.IsSubtypeOf(xdm.TypeFloat, xdm.TypeNumeric) || xdm.IsSubtypeOf(xdm.TypeBoolean, xdm.TypeNumeric) || xdm.IsSubtypeOf("Q{u}unknown", xdm.TypeAnyType) {
		t.Fatal("numeric or unknown ancestry")
	}
	if !xdm.IsStringDerived(xdm.TypeNCName) || xdm.IsStringDerived(xdm.TypeInteger) || !xdm.IsKnownXSDType(xdm.TypeNMTOKENS) || xdm.IsKnownXSDType("Q{u}unknown") {
		t.Fatal("derived type classification")
	}
}

func TestSchemaAnnotationNames(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		input, local, ns string
		ok               bool
	}{{"Q{urn:a}name", "name", "urn:a", true}, {"Q{}name", "name", "", true}, {"p:name", "name", "", true}, {"name", "name", "", true}, {"xs:string", "", "", false}, {"xsd:integer", "", "", false}, {"Q{broken", "", "", false}, {"Q{u}", "", "", false}, {"", "", "", false}} {
		local, ns, ok := xdm.SchemaAnnotationParts(tc.input)
		if local != tc.local || ns != tc.ns || ok != tc.ok {
			t.Fatalf("annotation %q: %q,%q,%v", tc.input, local, ns, ok)
		}
	}
	if xdm.QAnnotation("urn:a", "name") != "Q{urn:a}name" {
		t.Fatal("qualified annotation")
	}
}

func nestedFunctionType() xdm.SequenceType {
	return xdm.SequenceType{ItemTest: xdm.ArrayTest{MemberType: xdm.SequenceType{ItemTest: xdm.MapTest{KeyType: xdm.AtomicOrUnionType{Name: "string"}, ValType: xdm.SequenceType{ItemTest: xdm.FunctionTest{ParamTypes: []xdm.SequenceType{{ItemTest: xdm.AtomicOrUnionType{Name: "integer"}}}, ReturnType: xdm.SequenceType{ItemTest: xdm.AtomicOrUnionType{Name: "string"}}}}}}}}
}

func nestedParams(st xdm.SequenceType) []xdm.SequenceType {
	return st.ItemTest.(xdm.ArrayTest).MemberType.ItemTest.(xdm.MapTest).ValType.ItemTest.(xdm.FunctionTest).ParamTypes
}

func TestCloneFunctionMetadataRecursesThroughCollections(t *testing.T) {
	t.Parallel()

	input := nestedFunctionType()
	returnType := nestedFunctionType()
	sentinel := errors.New("function cause")
	function := xdm.FunctionItem{Arity: 1, Name: "f", ParamTypes: []xdm.SequenceType{input}, ReturnType: &returnType, Invoke: func(context.Context, []xdm.Sequence) (xdm.Sequence, error) {
		return xdm.SingleString("result"), sentinel
	}}
	cloned := xdm.CloneItem(function).(xdm.FunctionItem)
	nestedParams(function.ParamTypes[0])[0].Occurrence = xdm.OccurrenceZeroOrMore
	nestedParams(*function.ReturnType)[0].Void = true
	function.ParamTypes[0].Void = true
	if cloned.ParamTypes[0].Void || nestedParams(cloned.ParamTypes[0])[0].Occurrence != xdm.OccurrenceExactlyOne || nestedParams(*cloned.ReturnType)[0].Void {
		t.Fatal("cloned metadata shares nested slices")
	}
	result, err := cloned.Invoke(t.Context(), nil)
	if err != sentinel || cloned.Arity != 1 || cloned.Name != "f" { //nolint:errorlint // The callback error must be returned unchanged, preserving its identity.
		t.Fatal("clone changed function identity or closure")
	}
	assertStringItems(t, result, "result")
	if xdm.CloneSequenceTypes(nil) != nil || xdm.CloneSequenceTypePtr(nil) != nil || xdm.CloneSequences(nil) != nil {
		t.Fatal("nil cloning changed representation")
	}

	// FunctionTest return types recurse independently of parameter metadata.
	signature := xdm.SequenceType{ItemTest: xdm.FunctionTest{ReturnType: nestedFunctionType()}}
	signatureClone := xdm.CloneSequenceType(signature)
	nestedParams(signature.ItemTest.(xdm.FunctionTest).ReturnType)[0].Void = true
	if nestedParams(signatureClone.ItemTest.(xdm.FunctionTest).ReturnType)[0].Void {
		t.Fatal("function test return type shares nested parameter metadata")
	}

	plain := xdm.SequenceType{ItemTest: xdm.AnyItemTest{}, Occurrence: xdm.OccurrenceOneOrMore}
	if got := xdm.CloneSequenceType(plain); !reflect.DeepEqual(got, plain) {
		t.Fatal("immutable test metadata changed")
	}
	params := []xdm.SequenceType{plain, {Void: true}}
	for _, tc := range []struct {
		repeat bool
		index  int
		ok     bool
		want   xdm.SequenceType
	}{{false, -1, false, xdm.SequenceType{}}, {false, 0, true, plain}, {false, 1, true, params[1]}, {false, 2, false, xdm.SequenceType{}}, {true, 2, false, xdm.SequenceType{}}} {
		got, ok := xdm.FunctionParameterType(params, tc.repeat, tc.index)
		if ok != tc.ok || !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("parameter %d repeat%v: %+v,%v", tc.index, tc.repeat, got, ok)
		}
	}
	if got, ok := xdm.FunctionParameterType(params[:1], true, 1000); !ok || !reflect.DeepEqual(got, plain) {
		t.Fatal("compact repeated parameter lost metadata")
	}
	if _, ok := xdm.FunctionParameterType(nil, true, 0); ok {
		t.Fatal("empty repeated metadata matched")
	}
}

func TestCloneNodeItemMetadataPreservesIdentity(t *testing.T) {
	t.Parallel()

	doc, err := (xdm.ParseOptions{}).Parse(t.Context(), []byte("<root/>"))
	if err != nil {
		t.Fatal(err)
	}
	leaf := &xdm.NodeItemUnionMember{TypeName: "Q{u}leaf"}
	original := xdm.NodeItem{Node: doc.DocumentElement(), TypeAnnotation: "Q{u}union", ActiveUnionMember: leaf, UnionMemberTypes: []string{"first", "second"}, ListItemLeaves: []*xdm.NodeItemUnionMember{leaf, nil}}
	cloned := xdm.CloneItem(original).(xdm.NodeItem)
	original.UnionMemberTypes[0] = "changed"
	original.ListItemLeaves[0] = nil
	if cloned.Node != original.Node || cloned.ActiveUnionMember != leaf || cloned.ListItemLeaves[0] != leaf || cloned.UnionMemberTypes[0] != "first" || cloned.TypeAnnotation != "Q{u}union" {
		t.Fatal("metadata cloned incorrectly or node identity changed")
	}
	if got := xdm.CloneItem(xdm.NodeItem{Node: original.Node}).(xdm.NodeItem); got.Node != original.Node {
		t.Fatal("plain node clone changed identity")
	}
}

func TestNestedValuesOwnMutableInputs(t *testing.T) {
	t.Parallel()

	key := big.NewInt(7)
	number := big.NewRat(1, 10)
	array := xdm.NewArray([]xdm.Sequence{xdm.SingleDecimal(number)})
	value := xdm.NewMap([]xdm.MapEntry{{
		Key:   xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: key},
		Value: xdm.ItemSlice{array},
	}})
	key.SetInt64(9)
	number.SetInt64(3)

	for attempt := range 2 {
		seq, ok := value.Get(xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(7)})
		if !ok {
			t.Fatal("mutation changed the stored map key")
		}

		stored, ok := seq.Get(0).(xdm.ArrayItem)
		if !ok {
			t.Fatalf("stored value: %T", seq.Get(0))
		}

		member, err := stored.Get(1)
		if err != nil {
			t.Fatal(err)
		}

		atomic, ok := member.Get(0).(xdm.AtomicValue)
		if !ok || atomic.BigRat().Cmp(big.NewRat(1, 10)) != 0 {
			t.Fatalf("attempt %d: stored decimal changed: %v", attempt, member)
		}

		atomic.BigRat().SetInt64(42)
	}

	if _, ok := value.Get(xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(9)}); ok {
		t.Fatal("mutated key became visible")
	}
}

func TestMapPersistentUpdatesAndOwnership(t *testing.T) {
	t.Parallel()

	keyNumber, valueNumber := big.NewInt(7), big.NewInt(42)
	value := xdm.ItemSlice{xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: valueNumber}}
	original := xdm.NewMap([]xdm.MapEntry{{Key: xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: keyNumber}, Value: value}, {Key: stringKey("empty"), Value: nil}})
	keyNumber.SetInt64(8)
	valueNumber.SetInt64(99)
	value[0] = stringKey("overwritten")
	key := xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(7)}
	if original.Keys()[0].IntegerVal() != 7 {
		t.Fatal("constructor retained caller-owned key")
	}
	got, ok := original.Get(key)
	if !ok || got.Get(0).(xdm.AtomicValue).BigInt().Int64() != 42 || original.Contains(xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(8)}) {
		t.Fatal("constructor retained mutable inputs")
	}
	got.Get(0).(xdm.AtomicValue).BigInt().SetInt64(100)
	keys := original.Keys()
	keys[0].BigInt().SetInt64(100)
	view, ok := original.GetView(key)
	if !ok || view.Get(0).(xdm.AtomicValue).BigInt().Int64() != 42 || !original.Contains(key) {
		t.Fatal("Get or Keys exposed stored payload")
	}
	if got, ok = original.Get(stringKey("empty")); !ok || got != nil {
		t.Fatalf("present empty map value: %v,%v", got, ok)
	}
	if got, ok = original.Get(stringKey("absent")); ok || got != nil {
		t.Fatal("missing map key appears present")
	}
	updated := original.Put(key, xdm.SingleString("new")).Put(stringKey("third"), xdm.SingleString("third"))
	if original.Size() != 2 || updated.Size() != 3 {
		t.Fatal("Put changed source size")
	}
	got = requireMapValue(t, updated, key)
	assertStringItems(t, got, "new")
	if keys := updated.Keys(); keys[0].IntegerVal() != 7 || keys[1].StringVal() != "empty" || keys[2].StringVal() != "third" {
		t.Fatalf("replacement changed insertion order: %v", keys)
	}
	removed := updated.Remove(stringKey("empty"))
	if removed.Size() != 2 || removed.Contains(stringKey("empty")) || !updated.Contains(stringKey("empty")) {
		t.Fatal("Remove changed original or retained deleted key")
	}
	if removed.Remove(stringKey("missing")).Size() != 2 {
		t.Fatal("missing-key removal changed map")
	}
	single := xdm.SingleEntryMap(stringKey("only"), xdm.SingleString("value"))
	if !single.Contains(stringKey("only")) || single.Contains(stringKey("other")) {
		t.Fatal("single entry lookup")
	}
	got, ok = single.GetView(stringKey("only"))
	if !ok {
		t.Fatal("single view missing")
	}
	assertStringItems(t, got, "value")
	if _, ok = single.GetView(stringKey("other")); ok {
		t.Fatal("single view matches wrong key")
	}
	if single.Remove(stringKey("only")).Size() != 0 || single.Remove(stringKey("other")).Size() != 1 {
		t.Fatal("single removal")
	}
	grown := single.Put(stringKey("second"), nil).Put(stringKey("only"), xdm.SingleString("replacement"))
	if grown.Size() != 2 {
		t.Fatal("single entry update index")
	}
	got = requireMapValue(t, grown, stringKey("only"))
	assertStringItems(t, got, "replacement")
	empty := xdm.NewMap(nil)
	if empty.Contains(key) {
		t.Fatal("empty map contains key")
	}
	if _, ok = empty.Get(key); ok {
		t.Fatal("empty map Get")
	}
}

func TestMapIterationIsolationAndEarlyError(t *testing.T) {
	t.Parallel()

	m := xdm.NewMap([]xdm.MapEntry{{Key: xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: big.NewInt(1)}, Value: xdm.SingleIntegerBig(big.NewInt(10))}, {Key: stringKey("second"), Value: xdm.SingleString("v")}})
	sentinel := errors.New("stop after first")
	calls := 0
	err := m.ForEach(func(k xdm.AtomicValue, v xdm.Sequence) error {
		calls++
		k.BigInt().SetInt64(9)
		v.Get(0).(xdm.AtomicValue).BigInt().SetInt64(99)
		return sentinel
	})
	if err != sentinel || calls != 1 { //nolint:errorlint // The callback error must be returned unchanged, preserving its identity.
		t.Fatalf("ForEach error/stop: %v,%d", err, calls)
	}
	value, ok := m.Get(xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(1)})
	if !ok || value.Get(0).(xdm.AtomicValue).IntegerVal() != 10 {
		t.Fatal("ForEach exposed map storage")
	}
	calls = 0
	if err = m.ForEachView(func(xdm.AtomicValue, xdm.Sequence) error { calls++; return sentinel }); err != sentinel || calls != 1 { //nolint:errorlint // The callback error must be returned unchanged, preserving its identity.
		t.Fatal("ForEachView did not stop on exact error")
	}
	var seen []string
	if err = m.ForEach(func(k xdm.AtomicValue, _ xdm.Sequence) error { seen = append(seen, k.TypeName); return nil }); err != nil || !reflect.DeepEqual(seen, []string{xdm.TypeInteger, xdm.TypeString}) {
		t.Fatalf("iteration order: %v,%v", seen, err)
	}
	if err = m.ForEachView(func(xdm.AtomicValue, xdm.Sequence) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if len(m.EntriesView()) != 2 || len(m.KeysView()) != 2 {
		t.Fatal("entry views lost entries")
	}
}

func TestMapDuplicatePolicies(t *testing.T) {
	t.Parallel()

	for _, policy := range []xdm.MergePolicy{xdm.MergeUseFirst, xdm.MergeUseLast, xdm.MergeCombine, xdm.MergeReject} {
		t.Run(map[xdm.MergePolicy]string{xdm.MergeUseFirst: "first", xdm.MergeUseLast: "last", xdm.MergeCombine: "combine", xdm.MergeReject: "reject"}[policy], func(t *testing.T) {
			t.Parallel()

			entries := []xdm.MapEntry{{Key: stringKey("k"), Value: xdm.SingleString("a")}, {Key: stringKey("other"), Value: xdm.SingleString("middle")}, {Key: stringKey("k"), Value: xdm.SingleString("b")}, {Key: stringKey("k"), Value: xdm.SingleString("c")}}
			builder := xdm.NewMapBuilder(policy, 0)
			for i, entry := range entries {
				err := builder.Add(entry.Key, entry.Value)
				if policy == xdm.MergeReject && i >= 2 {
					requireXDMCode(t, err, "FOJS0003")
				} else if err != nil {
					t.Fatal(err)
				}
			}
			if builder.Size() != 2 {
				t.Fatalf("builder distinct keys: %d", builder.Size())
			}
			maps := make([]xdm.MapItem, len(entries))
			for i, entry := range entries {
				maps[i] = xdm.SingleEntryMap(entry.Key, entry.Value)
			}
			built := builder.Build()
			merged, err := xdm.MergeMaps(maps, policy)
			if policy == xdm.MergeReject {
				requireXDMCode(t, err, "FOJS0003")
				assertStringItems(t, requireMapValue(t, built, stringKey("k")), "a")
				assertStringItems(t, requireMapValue(t, built, stringKey("other")), "middle")
				if keys := built.Keys(); len(keys) != 2 || keys[0].StringVal() != "k" || keys[1].StringVal() != "other" {
					t.Fatalf("rejected duplicate changed key order: %v", keys)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range []xdm.MapItem{built, merged} {
				if m.Size() != 2 || m.Keys()[0].StringVal() != "k" || m.Keys()[1].StringVal() != "other" {
					t.Fatal("duplicate handling changed key order")
				}
				value, ok := m.Get(stringKey("k"))
				if !ok {
					t.Fatal("missing combined key")
				}
				switch policy {
				case xdm.MergeUseFirst:
					assertStringItems(t, value, "a")
				case xdm.MergeUseLast:
					assertStringItems(t, value, "c")
				case xdm.MergeCombine:
					assertStringItems(t, value, "a", "b", "c")
				}
			}
		})
	}
	b := xdm.NewMapBuilder(xdm.MergeCombine, 1)
	for _, v := range []xdm.Sequence{nil, xdm.SingleString("v"), nil, xdm.SingleString("w")} {
		if err := b.Add(stringKey("k"), v); err != nil {
			t.Fatal(err)
		}
	}
	value := requireMapValue(t, b.Build(), stringKey("k"))
	assertStringItems(t, value, "v", "w")
}

func TestMapConstructorsOwnMutableKeys(t *testing.T) {
	t.Parallel()

	for _, construct := range []func(xdm.AtomicValue) xdm.MapItem{
		func(k xdm.AtomicValue) xdm.MapItem { return xdm.SingleEntryMap(k, nil) },
		func(k xdm.AtomicValue) xdm.MapItem { return xdm.NewMap([]xdm.MapEntry{{Key: k, Value: nil}}) },
		func(k xdm.AtomicValue) xdm.MapItem {
			b := xdm.NewMapBuilder(xdm.MergeUseFirst, 1)
			if err := b.Add(k, nil); err != nil {
				t.Fatal(err)
			}
			return b.Build()
		},
	} {
		key := big.NewInt(7)
		m := construct(xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: key})
		key.SetInt64(9)
		if !m.Contains(xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(7)}) || m.Contains(xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(9)}) || m.Keys()[0].IntegerVal() != 7 {
			t.Fatal("map constructor retained mutable caller key")
		}
	}
}

func assertStringItems(t *testing.T, seq xdm.Sequence, want ...string) {
	t.Helper()
	var got []string
	for item := range xdm.SequenceItems(seq) {
		value, ok := item.(xdm.AtomicValue)
		if !ok {
			t.Fatalf("item type %T; want atomic string", item)
		}
		if value.TypeName != xdm.TypeString {
			t.Fatalf("atomic type %q; want xs:string", value.TypeName)
		}
		got = append(got, value.StringVal())
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("items %q; want %q", got, want)
	}
}

func stringKey(s string) xdm.AtomicValue { return xdm.AtomicValue{TypeName: xdm.TypeString, Value: s} }

func requireXDMCode(t *testing.T, err error, code string) {
	t.Helper()
	var xe *xdm.Error
	if !errors.As(err, &xe) || xe.Code != code {
		t.Fatalf("error %v; want XDM %s", err, code)
	}
}

func requireArrayMember(t *testing.T, array xdm.ArrayItem, index int) xdm.Sequence {
	t.Helper()
	member, err := array.Get(index)
	if err != nil {
		t.Fatalf("array.Get(%d): %v", index, err)
	}
	return member
}

func requireMapValue(t *testing.T, valueMap xdm.MapItem, key xdm.AtomicValue) xdm.Sequence {
	t.Helper()
	value, found := valueMap.Get(key)
	if !found {
		t.Fatalf("map.Get(%v): key absent", key)
	}
	return value
}

func TestMapKeyValueEquality(t *testing.T) {
	t.Parallel()

	date := time.Date(2020, 2, 29, 12, 30, 0, 123, time.UTC)
	cases := []struct {
		name                  string
		key, equal, different xdm.AtomicValue
	}{
		{"numeric domain", xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(1)}, xdm.AtomicValue{TypeName: xdm.TypeDecimal, Value: big.NewRat(2, 2)}, xdm.AtomicValue{TypeName: xdm.TypeDecimal, Value: big.NewRat(11, 10)}},
		{"big integer", xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: new(big.Int).Lsh(big.NewInt(1), 2000)}, xdm.AtomicValue{TypeName: "Q{u}huge", BaseType: xdm.TypeInteger, Value: new(big.Int).Lsh(big.NewInt(1), 2000)}, xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 2000), big.NewInt(1))}},
		{"exact decimal", xdm.AtomicValue{TypeName: xdm.TypeDecimal, Value: big.NewRat(9007199254740993, 2)}, xdm.AtomicValue{TypeName: "Q{u}decimal", BaseType: xdm.TypeDecimal, Value: big.NewRat(9007199254740993, 2)}, xdm.AtomicValue{TypeName: xdm.TypeDecimal, Value: big.NewRat(9007199254740992, 2)}},
		{"float rounding", xdm.AtomicValue{TypeName: "Q{u}float", BaseType: xdm.TypeFloat, Value: float64(16777217)}, xdm.AtomicValue{TypeName: xdm.TypeFloat, Value: xdm.NewFloat(16777216)}, xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: xdm.NewDouble(16777217)}},
		{"double integer boundary", xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: math.Ldexp(1, 63)}, xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: new(big.Int).Lsh(big.NewInt(1), 63)}, xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(math.MinInt64)}},
		{"negative zero", xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: xdm.NewDouble(math.Copysign(0, -1))}, xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(0)}, xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(-1)}},
		{"NaN", xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: xdm.NewDouble(math.NaN())}, xdm.AtomicValue{TypeName: xdm.TypeFloat, Value: xdm.NewFloat(math.NaN())}, xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: xdm.NewDouble(math.Inf(1))}},
		{"infinity", xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: math.Inf(1)}, xdm.AtomicValue{TypeName: xdm.TypeFloat, Value: xdm.NewFloat(math.Inf(1))}, xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: math.Inf(-1)}},
		{"URI string", xdm.AtomicValue{TypeName: xdm.TypeAnyURI, Value: "urn:a"}, stringKey("urn:a"), stringKey("urn:b")},
		{"untyped string", xdm.AtomicValue{TypeName: xdm.TypeUntypedAtomic, Value: "a"}, stringKey("a"), stringKey("b")},
		{"derived string", xdm.AtomicValue{TypeName: "Q{u}token", BaseType: xdm.TypeToken, Value: "a"}, stringKey("a"), stringKey("b")},
		{"derived URI", xdm.AtomicValue{TypeName: "Q{u}uri", BaseType: xdm.TypeAnyURI, Value: "urn:a"}, stringKey("urn:a"), stringKey("urn:b")},
		{"QName prefix", xdm.AtomicValue{TypeName: xdm.TypeQName, Value: xdm.QNameValue{Prefix: "p", Local: "name", URI: "urn:a"}}, xdm.AtomicValue{TypeName: xdm.TypeQName, Value: xdm.QNameValue{Prefix: "q", Local: "name", URI: "urn:a"}}, xdm.AtomicValue{TypeName: xdm.TypeQName, Value: xdm.QNameValue{Prefix: "p", Local: "name", URI: "urn:b"}}},
		{"time zone", xdm.AtomicValue{TypeName: xdm.TypeDateTime, Value: date}, xdm.AtomicValue{TypeName: xdm.TypeDateTime, Value: date.In(time.FixedZone("offset", 3*3600))}, xdm.AtomicValue{TypeName: xdm.TypeDateTime, Value: date.Add(time.Nanosecond)}},
		{"absent time zone", xdm.AtomicValue{TypeName: xdm.TypeDateTime, Value: time.Date(2020, 2, 29, 12, 30, 0, 0, xdm.NoTimezone())}, xdm.AtomicValue{TypeName: xdm.TypeDateTime, Value: time.Date(2020, 2, 29, 12, 30, 0, 0, xdm.NoTimezone())}, xdm.AtomicValue{TypeName: xdm.TypeDateTime, Value: time.Date(2020, 2, 29, 12, 30, 0, 0, time.UTC)}},
		{"binary content", xdm.AtomicValue{TypeName: xdm.TypeHexBinary, Value: []byte{0, 255}}, xdm.AtomicValue{TypeName: xdm.TypeHexBinary, Value: []byte{0, 255}}, xdm.AtomicValue{TypeName: xdm.TypeHexBinary, Value: []byte{0, 254}}},
		{"boolean domain", xdm.AtomicValue{TypeName: xdm.TypeBoolean, Value: true}, xdm.AtomicValue{TypeName: xdm.TypeBoolean, Value: true}, xdm.AtomicValue{TypeName: xdm.TypeBoolean, Value: false}},
		{"duration", xdm.AtomicValue{TypeName: xdm.TypeDuration, Value: xdm.Duration{Seconds: 1.5, FracSec: big.NewRat(1, 2)}}, xdm.AtomicValue{TypeName: "Q{u}duration", BaseType: xdm.TypeDayTimeDuration, Value: xdm.Duration{SecRat: big.NewRat(3, 2)}}, xdm.AtomicValue{TypeName: xdm.TypeDuration, Value: xdm.Duration{Seconds: 1.25, FracSec: big.NewRat(1, 4)}}},
		{"duration zero", xdm.AtomicValue{TypeName: xdm.TypeYearMonthDuration, Value: xdm.Duration{Negative: true}}, xdm.AtomicValue{TypeName: xdm.TypeDayTimeDuration, Value: xdm.Duration{}}, xdm.AtomicValue{TypeName: xdm.TypeYearMonthDuration, Value: xdm.Duration{Months: 1}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Exercise both the index-free single-entry and indexed lookup paths.
			for _, m := range []xdm.MapItem{xdm.SingleEntryMap(tc.key, xdm.SingleString("found")), xdm.NewMap([]xdm.MapEntry{{Key: tc.key, Value: xdm.SingleString("found")}, {Key: stringKey("unrelated"), Value: nil}})} {
				value, ok := m.Get(tc.equal)
				if !ok {
					t.Fatal("equal value missed stored key")
				}
				assertStringItems(t, value, "found")
				if m.Contains(tc.different) {
					t.Fatal("distinct value collided with stored key")
				}
			}
		})
	}
}

func TestMergeMapsCombineEmptyValues(t *testing.T) {
	t.Parallel()

	for _, values := range [][]xdm.Sequence{{nil, xdm.SingleString("a")}, {xdm.SingleString("a"), nil}, {nil, nil}} {
		maps := []xdm.MapItem{xdm.SingleEntryMap(stringKey("key"), values[0]), xdm.SingleEntryMap(stringKey("key"), values[1])}
		merged, err := xdm.MergeMaps(maps, xdm.MergeCombine)
		if err != nil {
			t.Fatal(err)
		}
		value, ok := merged.Get(stringKey("key"))
		if !ok || merged.Size() != 1 {
			t.Fatal("combining an empty value lost its key")
		}
		if xdm.SequenceLen(values[0])+xdm.SequenceLen(values[1]) == 0 {
			assertStringItems(t, value)
		} else {
			assertStringItems(t, value, "a")
		}
	}
}
