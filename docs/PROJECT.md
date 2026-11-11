# Project record

## Objective

Keyed pseudonymization with HMAC-SHA256 tokens per domain, key ids for rotation and re-identification through a bounded vault port, with a stated threat model

## Scope

- In scope: the public API documented in [README.md](../README.md), typed and tested.
- Out of scope: anything that needs runtime dependencies or I/O without an accepted ADR.

## Timeline

| Date | Event |
|---|---|
| 2026 | Repository created from the factory utility template. |

## Effort metrics

Measured values only; a value that has not been measured stays "pending measurement".

| Metric | Value |
|---|---|
| Tokens (input / output) | 858409 / 53887 |
| Hours (human) | pending measurement |
| Cost (USD) | 0.0766 |

## Factory run u288 (measured from API usage)

| Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|
| generation | deepseek-v4-pro | yes | 1800 | 20999 | 0 | 3200 | 0.0428 |
| fix-1 | deepseek-flash | no | 8593 | 542 | 0 | 19712 | 0.0017 |
| audit | deepseek-flash | no | 22241 | 11100 | 0 | 201216 | 0.0106 |
| fix-2 | deepseek-flash | no | 16187 | 3544 | 0 | 107136 | 0.0049 |
| threat-model | deepseek-flash | no | 31220 | 17702 | 0 | 447104 | 0.0166 |

Total: $0.0766. Prices: deepseek line, as measured by its adapter.
