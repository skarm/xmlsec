// Package xdm owns the values, sequence types, node identity and navigation
// shared by XPath and XSLT. Node views use internal/tree storage directly;
// parsing and ordinary XML output use the project's parser and writer.
//
// This package never depends on either language compiler or evaluator.
// Published documents are frozen; XSLT result construction uses private drafts.
package xdm
