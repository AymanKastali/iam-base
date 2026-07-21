package domain

// Event is a domain event: a past-tense fact about something that happened
// to an aggregate. Recorded by the aggregate that raised it; the app/infra
// layer pulls, timestamps, and publishes it after the aggregate's change
// commits — domain itself stays clock-free.
type Event interface {
	EventName() string
}
