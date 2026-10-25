package main

func Example() {
	if err := run(); err != nil {
		panic(err)
	}
	// Output:
	// RSA-PSS: hash=SHA-384 mgf=SHA-384 salt=24 references=1 container-covered=false
	// HMAC: output-bits=256 references=1 container-covered=false
}
