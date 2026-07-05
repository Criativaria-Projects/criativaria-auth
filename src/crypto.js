// HMAC-SHA256 signing — re-exported from the shared Criativaria auth-crypto
// package (see career-tools/docs/adr/0002-shared-auth-crypto-package-defer-jwt-migration.md).
// This used to be a copy-pasted implementation, diverging slightly from
// career-tools's and clt-pj-calculator's copies of the same logic. No change
// to token format, secrets, or wire behavior — see the package's own tests
// for crypto round-trip coverage.
export { sign, verify } from '@criativaria-projects/auth-crypto'
