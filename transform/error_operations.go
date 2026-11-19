package transform

const (
	xsltOperationSuffix  = " XSLT"
	opAnalyzeXPath       = "analyze XPath"
	opArrayMember        = "array member"
	opCompileXPath       = "compile XPath"
	opCompileXSLT        = "compile" + xsltOperationSuffix
	opConfigure          = "configure"
	opEvaluateXPath      = "evaluate XPath"
	opExecuteXSLT        = "execute" + xsltOperationSuffix
	opExport             = "export"
	opImport             = "import"
	opImportNode         = "import node"
	opMap                = "map"
	opOutputEncoding     = "output encoding"
	opParse              = "parse"
	opResultDocument     = "result document"
	opSerializeXSLT      = "serialize" + xsltOperationSuffix
	opStreamXSLT         = "stream" + xsltOperationSuffix
	opTransformXSLT      = "transform" + xsltOperationSuffix
	opWriteSecondaryXSLT = "write secondary" + xsltOperationSuffix
	opWriteXSLT          = "write" + xsltOperationSuffix
)
