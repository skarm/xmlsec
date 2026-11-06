package lexicon

// Catalog element local names. Match NamespaceCatalog as well; a matching local
// name alone does not identify a catalog entry or authorize resource access.
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

// Catalog attribute names are unqualified. AttrName is also reused as the local
// name in other XML vocabularies, whose namespaces and rules remain separate.
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

// Values of the catalog prefer attribute select public/system identifier
// precedence; they do not grant permission to read the selected resource.
const (
	PreferPublic = "public"
	PreferSystem = "system"
)
