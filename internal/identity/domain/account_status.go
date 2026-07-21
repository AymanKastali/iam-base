package domain

type AccountStatus int

const (
	StatusActive AccountStatus = iota
	StatusDisabled
)
