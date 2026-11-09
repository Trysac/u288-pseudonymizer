# trysac-pseudonymizer

Keyed pseudonymization with HMAC-SHA256 tokens per domain, key ids for rotation,
and re-identification through a bounded vault.

Analytics and test environments need records that can be joined by person without
exposing who the person is, while support still needs to re-identify a record on
request. Plain hashing of emails is reversible by dictionary attack and links the
same value across every dataset. This library produces keyed, domain-separated
tokens that carry their key id, and re-identifies them only through an explicit
vault.

## Installation

```bash
pip install trysac-pseudonymizer
```

## Usage

```python
from pseudonymizer import Pseudonymizer, InMemoryVault

keys = {"k1": bytes(range(32))}
vault = InMemoryVault()
p = Pseudonymizer(keys, "k1", vault=vault)
token = p.pseudonymize("ana@example.com", domain="email")
print(token)  # pz_k1_wktl6nutd3rd4p2xsepvga2sid
print(p.reidentify(token))  # ana@example.com
```

Values are used exactly as given; callers should normalise values if needed.
Domains must match `^[a-z0-9_]{1,32}$`, key ids `^[a-z0-9]{1,8}$`, and values
must be 1-4096 characters.

## CLI

```bash
export PSEUDO_KEY=$(python -c 'import os; print(os.urandom(32).hex())')
printf 'ana@example.com\n' | python -m pseudonymizer --key-env PSEUDO_KEY --key-id k1 --domain email
```

Reads UTF-8 lines from stdin, skipping empty lines, and prints one token per
line. Exits 0 on success, 1 on invalid values, 2 on usage or missing key.

## API

- `Pseudonymizer(keys, active_key_id, *, vault=None, on_event=None)`
- `.pseudonymize(value, *, domain, key_id=None) -> str`
- `.pseudonymize_record(record, fields) -> dict`
- `.reidentify(token) -> str`
- `InMemoryVault(max_entries=1_000_000)`
- `PseudoError` with stable `code` attributes.

See `docs/SECURITY.md` for the threat model and `docs/ARCHITECTURE.md` for design
notes.
