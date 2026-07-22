package domain

// ValueObject is implemented by immutable, self-validating domain values
// with no identity of their own — equal when their attributes are equal.
type ValueObject[T any] interface {
	Equals(other T) bool
}
