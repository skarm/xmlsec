// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

// Package stream writes XML incrementally to an io.Writer without building
// a result tree. NewWriter constructs a writer; configure indentation, quote
// style and XML version before the first write.
//
// StartDocument, StartElement and the Write methods emit content. EndElement
// and EndDocument finish open structures. Errors are sticky: check Writer.Error
// after a sequence of calls. A failed operation can leave partial output, and
// the writer never closes the destination.
//
// Writer retains open-element and namespace state, so memory use depends on
// nesting and declarations. A Writer is not safe for concurrent use, and copies
// made after writing begins can share stack storage and the output destination.
package stream
