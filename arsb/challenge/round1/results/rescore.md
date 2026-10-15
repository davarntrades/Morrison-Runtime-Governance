| Variant | AUTH | EVD | FCL | LOC | RES | TEN | TRJ | UTL | XAG |
|---|---|---|---|---|---|---|---|---|---|
| published (frozen rule, frozen adapters) | M, M-med, P | M, M-med | M, M-med | C, M, M-med, P, refprov | M-med | C, M, M-med | C | allow, P, refprov, ungov | M, M-med |
| A1 camel -> camel-faithful | **C, M, M-med, P** | M, M-med | M, M-med | **C** | M-med | C, M, M-med | C | **allow, C, P, refprov, ungov** | M, M-med |
| A2 progent -> progent-callable | M, M-med, P | M, M-med | M, M-med | C, M, M-med, P, refprov | M-med | **C, M, M-med, P** | **C, P** | allow, P, refprov, ungov | M, M-med |
| A1+A2 | **C, M, M-med, P** | M, M-med | M, M-med | **C** | M-med | **C, M, M-med, P** | **C, P** | **allow, C, P, refprov, ungov** | M, M-med |
| S1 SPEC §7 literal: CaMeL UNSUPPORTED where approval is needed | M, M-med, P | M, M-med | M, M-med | **M, M-med, P, refprov** | M-med | C, M, M-med | C | allow, P, refprov, ungov | M, M-med |
| S2 no leader unless >=2 distinct non-reference systems runnable | M, M-med, P | **none** | **none** | C, M, M-med, P, refprov | M-med | C, M, M-med | C | allow, P, refprov, ungov | M, M-med |
| S3 reference baselines cannot lead | M, M-med, P | M, M-med | M, M-med | **C, M, M-med, P** | M-med | C, M, M-med | C | **P** | M, M-med |
| S4 scenario-weighted (not repetition-weighted) | M, M-med, P | M, M-med | M, M-med | C, M, M-med, P, refprov | M-med | C, M, M-med | C | allow, P, refprov, ungov | M, M-med |
| S5 ties within overlapping 95% Wilson intervals | M, M-med, P | M, M-med | M, M-med | **allow, C, M, M-med, P, refprov** | M-med | C, M, M-med | **C, M, M-med, refprov** | **allow, C, M, M-med, P, refprov, ungov** | M, M-med |
| S5 + A1 + A2 | **C, M, M-med, P** | M, M-med | M, M-med | **allow, C, M, M-med, P, refprov** | M-med | **C, M, M-med, P** | **C, M, M-med, P, refprov** | **allow, C, M, M-med, P, refprov, ungov** | M, M-med |
