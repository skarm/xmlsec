package main

func Example() {
	if err := run(); err != nil {
		panic(err)
	}
	// Output:
	// PKCS#8 key restored; PKCS#12 certificate "example document signer", 1 extra certificate
}
