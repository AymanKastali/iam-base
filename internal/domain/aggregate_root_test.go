package domain

import "testing"

type testEvent struct{ name string }

func (e testEvent) EventName() string { return e.name }

func TestAggregateRoot_RecordAndDrainEvents(t *testing.T) {
	root := NewAggregateRoot("agg-1")

	if got := root.RecordedEvents(); len(got) != 0 {
		t.Fatalf("RecordedEvents() = %d events, want 0 before recording anything", len(got))
	}

	root.RecordEvent(testEvent{name: "first"})
	root.RecordEvent(testEvent{name: "second"})

	events := root.RecordedEvents()
	if len(events) != 2 {
		t.Fatalf("RecordedEvents() = %d events, want 2", len(events))
	}
	if events[0].EventName() != "first" || events[1].EventName() != "second" {
		t.Errorf("RecordedEvents() = %v, want [first second] in order", events)
	}

	root.DrainEvents()
	if got := root.RecordedEvents(); len(got) != 0 {
		t.Fatalf("RecordedEvents() after DrainEvents() = %d events, want 0", len(got))
	}
}

func TestAggregateRoot_RecordedEventsReturnsCopy(t *testing.T) {
	root := NewAggregateRoot("agg-1")
	root.RecordEvent(testEvent{name: "first"})

	events := root.RecordedEvents()
	events[0] = testEvent{name: "mutated"}

	if got := root.RecordedEvents(); got[0].EventName() != "first" {
		t.Errorf("mutating the returned slice affected the aggregate's internal state: got %v", got)
	}
}
