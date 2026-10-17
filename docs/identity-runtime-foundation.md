# Edge identity foundation (development)

`oan_protocol::identity_runtime` contains an experimental typed context for message identity binding, mirrored by the TypeScript SDK. It is a body model, not a new signed HTTP envelope. Existing registration contracts, hashes, proofs and service routes are unchanged. Parsing a context proves no identity or authorization.

The synthetic fixture in `test-fixtures/identity-runtime/message-context.json` is checked by Rust and TypeScript tests. Cryptographic cross-language message vectors, challenge/session contracts and Runtime IPC still require implementation before interoperability can be claimed. The existing `oan-service-security` envelope remains the HTTP transport proof boundary.
