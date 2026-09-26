# Security policy

EffectLatch is an unreleased research implementation. Do not use it for hostile anonymous workloads, confidential production data, or irreversible real-world actions. Only the current development branch is supported; no security response period is promised.

Do not post live secrets, customer data, or private-environment exploit details in a public issue. Ask for a private reporting channel without including exploit details.

Run workers in the documented Linux profile. Do not mount the Docker socket or a home directory into workers. Do not enable WASI, direct guest sockets, or generic HTTP and shell imports. Keep secrets out of guest input, use generated local credentials, and bind the API to loopback by default.

Revocation prevents new intent commits after its transaction; it cannot recall an already authorized remote request. Arbitrary remote effects do not have a universal exactly-once guarantee. Local hash chains cannot protect against a trusted administrator who controls the database and keys. Passing individual tests does not prove general isolation. Independent reproduction and raw evidence are required before security or deployment claims.
