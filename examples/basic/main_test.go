package main

func Example() {
	if err := run(); err != nil {
		panic(err)
	}
	// Output:
	// Verified 1 reference(s), method http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256
	// #invoice-1: digest=3ce9b9d07165b4d7a4c24b693ec57334f4e55cd6fbace63132601b06df0b986e, bytes=100
}
