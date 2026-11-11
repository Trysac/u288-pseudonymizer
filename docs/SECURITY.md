# Security

This library implements keyed pseudonymization using HMAC-SHA256 tokens. The
security properties below follow from the design.

## Defended

- **Dictionary attack without the key**: tokens are HMAC-SHA256, not a plain
  hash of the value. An attacker who does not hold the key cannot compute or
  verify a token for a guessed value.
- **Linkage across domains**: the domain string is part of the HMAC input, so
  the same value produces different tokens in different domains.
- **Key rotation**: tokens embed the key id (`pz_<key-id>_...`). Old tokens
  remain re-identifiable through the vault even after the active key changes.
- **Secret hygiene**: key material never appears in `repr()`, event
  dictionaries, error messages, or logs.

## Not defended

- **Brute force of low-entropy values by someone holding the key**: an attacker
  with the key can enumerate common values for a domain and compare tokens.
- **Compromise of the vault**: the vault stores the mapping from token to value;
  if it is compromised, re-identification becomes possible for stored tokens.
- **Frequency analysis**: tokens are deterministic per (domain, key, value), so
  identical values produce identical tokens within that scope.
- **Pseudonymised data remains personal data**: as noted in GDPR Recital 26,
  pseudonymised data is still personal data; it is not anonymised.

## Operational guidance

- Protect the key material; store keys in a secrets manager.
- Protect the vault; consider encryption at rest and access controls.
- Normalise values before pseudonymization to avoid trivial variations.
- Use a different key per deployment or environment to further limit linkage.
