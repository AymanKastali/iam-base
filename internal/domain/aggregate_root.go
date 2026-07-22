package domain

// AggregateRoot is an Entity that is also a consistency boundary: it records
// the domain events its behavior raises. The app layer reads and clears them
// after the aggregate's change commits (see bounded-contexts for crossing a
// context boundary with an integration event instead).
type AggregateRoot[ID comparable] struct {
	Entity[ID]
	events []Event
}

func NewAggregateRoot[ID comparable](id ID) AggregateRoot[ID] {
	return AggregateRoot[ID]{Entity: NewEntity(id)}
}

// RecordEvent appends a domain event raised by this aggregate's behavior.
func (a *AggregateRoot[ID]) RecordEvent(event Event) {
	a.events = append(a.events, event)
}

// RecordedEvents returns a copy of the events recorded so far.
func (a *AggregateRoot[ID]) RecordedEvents() []Event {
	events := make([]Event, len(a.events))
	copy(events, a.events)
	return events
}

// DrainEvents clears the recorded events.
func (a *AggregateRoot[ID]) DrainEvents() {
	a.events = nil
}
