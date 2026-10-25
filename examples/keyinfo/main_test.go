package main

func Example() {
	if err := run(); err != nil {
		panic(err)
	}
	// Output:
	// references=1 payload-covered=true signature-container-covered=false
	// verified payload: message whose exact Object must be signed
}
