package testcert_test

import (
	"errors"
	"fmt"
	"testing"
)

type fixtureFatal struct{ err error }

type fixtureTB struct{ testing.TB }

func (fixtureTB) Fatal(args ...any) {
	if len(args) == 1 {
		if err, ok := args[0].(error); ok {
			panic(fixtureFatal{err})
		}
	}
	panic(fixtureFatal{errors.New(fmt.Sprint(args...))})
}

func (fixtureTB) Fatalf(format string, args ...any) {
	panic(fixtureFatal{fmt.Errorf(format, args...)})
}

func captureFixtureFatal(t *testing.T, run func(testing.TB)) (err error) {
	t.Helper()
	defer func() {
		stopped := recover()
		if stopped == nil {
			t.Fatal("fixture helper returned without a fatal error")
		}
		failure, ok := stopped.(fixtureFatal)
		if !ok {
			panic(stopped)
		}
		err = failure.err
	}()
	run(fixtureTB{t})
	return nil
}
