package domain

// Entity is a domain object with a stable identity — equality is by ID,
// never by attributes. Aggregates and other domain objects with a lifecycle
// embed Entity[ID] to get identity-based equality for free.
type Entity[ID comparable] struct {
	id ID
}

func NewEntity[ID comparable](id ID) Entity[ID] {
	return Entity[ID]{id: id}
}

func (e Entity[ID]) ID() ID {
	return e.id
}

func (e Entity[ID]) Equals(other Entity[ID]) bool {
	return e.id == other.id
}
