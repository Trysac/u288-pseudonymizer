# Use keyed HMAC-SHA256 pseudonymization with vault-based re-identification

Status: accepted (generated, pending human review)

## Context

Analytics and test environments need joinable records without exposing identities, while support must be able to re-identify a record on request. Plain hashing is vulnerable to dictionary attacks and links values across datasets.

## Decision

Implement deterministic, domain-separated HMAC-SHA256 tokens that embed a key id, and require an explicit vault for re-identification. Keys are at least 32 bytes; domains and key ids are validated by regex; tokens carry a 130-bit base32 fragment. The vault is bounded and writes occur on every pseudonymization call so tokens remain re-identifiable regardless of the key that produced them.

## Consequences

Tokens are deterministic within a domain/key, enabling frequency analysis; re-identification requires the vault, which becomes a critical asset; key rotation is supported by storing old keys and using the key id in tokens. Pseudonymised data remains personal data under GDPR Recital 26.
