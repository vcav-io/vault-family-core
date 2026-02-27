# Security Policy

## Reporting a Vulnerability

vault-family-core implements the cryptographic foundation of the VCAV protocol family.
Security researchers who discover vulnerabilities are asked to disclose responsibly
via **GitHub Security Advisories** rather than opening a public issue.

To report a vulnerability:

1. Go to the [Security tab](../../security/advisories) of this repository.
2. Click **New draft security advisory**.
3. Describe the vulnerability, affected versions, and (if known) a minimal reproduction.
4. Submit the draft — maintainers will respond within 5 business days.

## Scope

The following components are in scope for security research:

- **Ed25519 signing and verification** (`receipt-core`, `message-envelope`, `afal-core`)
- **Receipt generation and tamper detection** (`receipt-core`)
- **Canonicalization / RFC 8785 JCS implementation** (`receipt-core::canonicalize`)
- **IFC label algebra and policy evaluation** (`ifc-engine`)
- **AFAL wire types and signing** (`afal-core`)
- **JSON Schema validation** (`verifier-core::schema_validator`)
- **WASM verification surface** (`verifier-wasm`, `ifc-wasm`)

Out-of-scope: build tooling, CI configuration, documentation errors.

## Disclosure Policy

- Maintainers will acknowledge receipt within 5 business days.
- A fix will be prepared in a private fork and coordinated with the reporter before public disclosure.
- Credit will be given in the release notes unless the reporter requests anonymity.
