# DORAOps Architecture

## v0.1 boundary

v0.1 is an offline ICT third-party arrangement register core. It models providers, business functions, arrangements, data-location countries, critical-function binding, exit-plan evidence, substitutability assessment, and subcontracting indicators.

The validator checks structural completeness and referential integrity. It does **not** claim to reproduce every template/field in Implementing Regulation (EU) 2024/2956 and does not determine DORA compliance.

```text
ICTProvider + BusinessFunction + ICTArrangement
                    |
                    v
              RegisterBundle
                    |
                    v
             RegisterValidator
                    |
                    v
       RegisterValidationReport
```

Later releases can map this normalized graph into the official register-of-information template family without conflating data-shape validation with legal applicability.
