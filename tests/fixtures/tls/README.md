This certificate and private key are public, synthetic test fixtures only.
They must never be used to secure a real service. Tests use an in-process socket
pair, not a listening server or external network.

`targetlab-cert.pem` / `targetlab-key.pem` are a second public, synthetic pair whose
subjectAltName is `IP:127.0.0.1`. They exist only so tests and local demos can
serve the deliberately vulnerable TargetLab over TLS. The key is a test fixture,
not a secret, and must never secure anything real.
