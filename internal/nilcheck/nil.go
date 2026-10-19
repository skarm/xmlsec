// Package nilcheck checks application-supplied interfaces for nil values.
package nilcheck

import "reflect"

// IsNil reports whether value is nil or contains a nil pointer, map, slice,
// channel or function. Empty, non-nil maps and slices are not nil.
func IsNil(value any) bool {
	if value == nil {
		return true
	}

	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Chan, reflect.Func:
		return v.IsNil()
	}

	return false
}
