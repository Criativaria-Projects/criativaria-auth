# Security test run log — auth.criativaria

| date | tester | families | probes | result | findings (caido ids) | notes |
|---|---|---|---|---|---|---|
| 2026-07-21 | kimi (caido-pentest) | T1+T2+T3 | 10 | CLEAN (9/9 expectations met, cookie flags ok) | none | open-redirect candidates all 400; callback 4xx; health minimal; cookie HttpOnly+Secure+SameSite=Lax; control entryId 30 |
