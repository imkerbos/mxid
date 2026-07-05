package access

// Domain event types emitted for the audit subsystem.
const (
	EventRequestCreated   = "access.request.created"
	EventRequestApproved  = "access.request.approved"
	EventRequestRejected  = "access.request.rejected"
	EventRequestCancelled = "access.request.cancelled"
	EventGrantActivated   = "access.grant.activated"
	EventGrantExpired     = "access.grant.expired"
	EventGrantRevoked     = "access.grant.revoked"

	// Eligibility (policy config) lifecycle. These are admin writes that change
	// WHO may request elevation and under what constraints — as security-relevant
	// as the request lifecycle, so they emit typed events instead of relying on
	// the generic api.* catch-all.
	EventEligibilityCreated = "access.eligibility.created"
	EventEligibilityUpdated = "access.eligibility.updated"
	EventEligibilityDeleted = "access.eligibility.deleted"
)
