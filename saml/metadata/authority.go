package metadata

import "slices"

func requiredRoleEndpoint(kind RoleType) string {
	switch kind {
	case IdentityProvider:
		return SingleSignOnService
	case ServiceProvider:
		return AssertionConsumerService
	case AuthenticationAuthority:
		return AuthnQueryService
	case AttributeAuthority:
		return AttributeService
	case PolicyDecisionPoint:
		return AuthzService
	default:
		return ""
	}
}

func isAuthorityRole(kind RoleType) bool {
	return kind == AuthenticationAuthority || kind == AttributeAuthority || kind == PolicyDecisionPoint
}

func validRoleEndpoint(kind RoleType, endpoint string) bool {
	return slices.Contains(roleEndpointOrder(kind), endpoint)
}

func roleEndpointOrder(kind RoleType) []string {
	switch kind {
	case IdentityProvider:
		return []string{ArtifactResolutionService, SingleLogoutService, ManageNameIDService, nameNameIDFormat, SingleSignOnService, NameIDMappingService, AssertionIDRequestService}
	case ServiceProvider:
		return []string{ArtifactResolutionService, SingleLogoutService, ManageNameIDService, nameNameIDFormat, AssertionConsumerService}
	default:
		return []string{requiredRoleEndpoint(kind), AssertionIDRequestService, nameNameIDFormat}
	}
}
