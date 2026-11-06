package session

import (
	"context"
	"slices"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/saml/protocol"
)

type preparedReply struct {
	status  protocol.Status
	message *document.Document
}
type preparedReplies []preparedReply

// Prepare all store outcomes before committing local state. A failed signer
// therefore cannot change a name or invalidate sessions without a usable reply.
func (s Service) prepareReplies(ctx context.Context, kind, requestID, endpoint string, at time.Time) (preparedReplies, error) {
	statuses := []protocol.Status{
		{Code: protocol.Success},
		{Code: protocol.Success, Subcodes: []string{protocol.PartialLogout}},
		{Code: protocol.Requester, Subcodes: []string{protocol.UnknownPrincipal}},
		{Code: protocol.Requester},
	}

	replies := make(preparedReplies, 0, len(statuses))
	for _, status := range statuses {
		d, err := protocol.SignStatusResponse(ctx, protocol.StatusResponse{
			Issuer:       s.EntityID,
			Destination:  endpoint,
			IssueInstant: at,
			Kind:         kind,
			InResponseTo: requestID,
			Status:       status,
		}, s.Signing)
		if err != nil {
			return nil, err
		}

		replies = append(replies, preparedReply{status: status, message: d})
	}

	return replies, nil
}

func (replies preparedReplies) selectReply(status protocol.Status) (*document.Document, error) {
	for _, r := range replies {
		if r.status.Code == status.Code && slices.Equal(r.status.Subcodes, status.Subcodes) && status.Message == "" {
			return r.message, nil
		}
	}

	return nil, ErrState
}
