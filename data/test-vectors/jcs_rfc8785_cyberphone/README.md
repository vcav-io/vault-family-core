# RFC 8785 reference test data

The `input/` and `output/` files are copied unmodified from the RFC 8785 reference
implementation repository:

- Source: https://github.com/cyberphone/json-canonicalization/tree/32a48195b9b20fe67b1795e39e4509f14d860b45/testdata
- Copyright 2018 Anders Rundgren
- Licence: Apache License, Version 2.0 (see `LICENSE-APACHE` at the repository root)

`cargo run -p receipt-core --example vcav-generate-v3-vectors` checks that the Rust
canonicaliser reproduces every `output/` file and folds the cases into
`../jcs_rfc8785_testdata.json`.
