CREATE TABLE accounts (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    credential_hash TEXT NOT NULL,
    credential_alg TEXT NOT NULL,
    credential_version INT NOT NULL,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
