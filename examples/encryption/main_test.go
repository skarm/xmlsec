package main

func Example() {
	if err := run(); err != nil {
		panic(err)
	}
	// Output:
	// Restored Payload in Envelope; original payload is private; header is visible
	// Restored content of Payload: private; header is visible
	// Authenticated direct-key ciphertext from the exact external resource
}
