// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package lexicon

const (
	ElemGroup          = "group"
	ElemPublic         = "public"
	ElemSystem         = "system"
	ElemURI            = "uri"
	ElemRewriteSystem  = "rewriteSystem"
	ElemRewriteURI     = "rewriteURI"
	ElemDelegatePublic = "delegatePublic"
	ElemDelegateSystem = "delegateSystem"
	ElemDelegateURI    = "delegateURI"
	ElemNextCatalog    = "nextCatalog"
)

const (
	AttrPrefer              = "prefer"
	AttrPublicID            = "publicId"
	AttrPublicIDStartString = "publicIdStartString"
	AttrSystemID            = "systemId"
	AttrSystemIDStartString = "systemIdStartString"
	AttrURI                 = "uri"
	AttrURIStartString      = "uriStartString"
	AttrRewritePrefix       = "rewritePrefix"
	AttrCatalog             = "catalog"
	AttrName                = "name"
)

const (
	PreferPublic = "public"
	PreferSystem = "system"
)
