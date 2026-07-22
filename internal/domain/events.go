package domain

const (
	eventNameAccountRegistered = "identity.account_registered"
	eventNameAccountDisabled   = "identity.account_disabled"
	eventNameAccountActivated  = "identity.account_activated"
)

var _ Event = AccountRegistered{}

// AccountRegistered is raised when a new Account is created.
type AccountRegistered struct {
	AccountID AccountID
}

func (e AccountRegistered) EventName() string {
	return eventNameAccountRegistered
}

var _ Event = AccountDisabled{}

// AccountDisabled is raised when an Account transitions to disabled.
type AccountDisabled struct {
	AccountID AccountID
}

func (e AccountDisabled) EventName() string {
	return eventNameAccountDisabled
}

var _ Event = AccountActivated{}

// AccountActivated is raised when a disabled Account is reactivated.
type AccountActivated struct {
	AccountID AccountID
}

func (e AccountActivated) EventName() string {
	return eventNameAccountActivated
}

const (
	eventNameRefreshTokenFamilyIssued  = "identity.refresh_token_family_issued"
	eventNameRefreshTokenFamilyRotated = "identity.refresh_token_family_rotated"
	eventNameRefreshTokenFamilyRevoked = "identity.refresh_token_family_revoked"
)

var _ Event = RefreshTokenFamilyIssued{}

// RefreshTokenFamilyIssued is raised when a new RefreshTokenFamily is created (on login).
type RefreshTokenFamilyIssued struct {
	FamilyID  FamilyID
	AccountID AccountID
}

func (e RefreshTokenFamilyIssued) EventName() string {
	return eventNameRefreshTokenFamilyIssued
}

var _ Event = RefreshTokenFamilyRotated{}

// RefreshTokenFamilyRotated is raised when a family's refresh token is rotated.
type RefreshTokenFamilyRotated struct {
	FamilyID FamilyID
}

func (e RefreshTokenFamilyRotated) EventName() string {
	return eventNameRefreshTokenFamilyRotated
}

var _ Event = RefreshTokenFamilyRevoked{}

// RefreshTokenFamilyRevoked is raised when a family is revoked, either explicitly
// (logout) or defensively (a reused/superseded token was presented).
type RefreshTokenFamilyRevoked struct {
	FamilyID FamilyID
}

func (e RefreshTokenFamilyRevoked) EventName() string {
	return eventNameRefreshTokenFamilyRevoked
}
