# Throwaway TLS fixtures (test-only)

Everything in this directory is throwaway test material for
`test/analytics-sinks.test.ts`. None of it protects anything; never use it
outside the tests.

- `throwaway-test-only.{key,crt}`: self-signed P-256 certificate, `CN=analytics-test-only`,
  SAN `IP:127.0.0.1, DNS:localhost`, `CA:TRUE`. It is both the trusted CA
  (`SELFHOST_ANALYTICS_COLLECTOR_CA_FILE`) and the valid-host server certificate.
- `throwaway-wrong-name.{key,crt}`: P-256 leaf signed by the certificate above, SAN
  `DNS:wrong-name.invalid` only, so it chains to the trusted CA but does not cover
  `127.0.0.1` or `localhost` (hostname-mismatch case).

The wrong-name leaf was generated with (validity matches the CA, 36500 days):

```sh
cat > wrong-name.ext <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:wrong-name.invalid
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EXT
openssl ecparam -name prime256v1 -genkey -noout -out throwaway-wrong-name.key
openssl req -new -key throwaway-wrong-name.key -subj "/CN=wrong-name.invalid" -out wrong-name.csr
openssl x509 -req -in wrong-name.csr -CA throwaway-test-only.crt -CAkey throwaway-test-only.key \
  -set_serial 0x$(openssl rand -hex 16) -days 36500 -sha256 -extfile wrong-name.ext \
  -out throwaway-wrong-name.crt
openssl verify -CAfile throwaway-test-only.crt throwaway-wrong-name.crt
```
