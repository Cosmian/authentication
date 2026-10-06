# cosmian-auth-verifier

Helm chart for deploying the [Cosmian Authentication Server](https://github.com/Cosmian/authentication)
(`auth_verifier`) — realms, username/password, TOTP, JWT/OIDC, mTLS and
optional SAML 2.0 single sign-on — on Kubernetes.

The chart renders `auth_verifier.toml` from `authVerifier.*` values. Database
URLs are read from a Secret and substituted when the container starts, so no
credentials end up in the ConfigMap.

## Prerequisites

The server terminates TLS itself. Create the TLS Secret first (certificate,
PKCS#8 private key and CA chain). Unless `authVerifier.sessionJwt` is set, the
same key signs session JWTs and must be EC P-256. With cert-manager:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: auth-verifier-tls
spec:
  secretName: auth-verifier-tls # contains tls.crt, tls.key, ca.crt
  dnsNames: [auth.example.com]
  privateKey:
    algorithm: ECDSA
    size: 256
    encoding: PKCS8
  issuerRef:
    name: my-issuer
    kind: ClusterIssuer
```

## Quick start

```bash
# Default image, sqlite backend on a PVC
helm install auth ./charts/cosmian-auth-verifier \
  --set authVerifier.tls.existingSecret=auth-verifier-tls

# Production: PostgreSQL (Secret with key "database-url") + Redis sessions
helm install auth ./charts/cosmian-auth-verifier \
  --set authVerifier.tls.existingSecret=auth-verifier-tls \
  --set authVerifier.database.backend=postgresql \
  --set authVerifier.database.existingSecret=auth-db \
  --set authVerifier.sessionStore.enabled=true \
  --set authVerifier.sessionStore.existingSecret=auth-sessions \
  --set replicaCount=2

# SAML: switches to the <version>-saml image and configures the SP signing key
kubectl create secret tls auth-saml-sp --cert=saml-sp.cert.pem --key=saml-sp.key.pem
helm install auth ./charts/cosmian-auth-verifier \
  --set authVerifier.tls.existingSecret=auth-verifier-tls \
  --set saml.enabled=true \
  --set saml.existingSecret=auth-saml-sp
```

The SAML SP key must be RSA (>= 2048 bits), for example:

```bash
openssl req -x509 -newkey rsa:3072 -sha256 -days 730 -nodes -subj "/CN=auth-saml-sp" \
  -keyout saml-sp.key.pem -out saml-sp.cert.pem
```

Per-realm IdP settings (entity ID, SSO URL, ACS URL, …) are then managed
through the API or the admin UI; see `server/documentation/docs/saml.md`.

## Secrets reference

| Value                                  | Keys                          |
| -------------------------------------- | ----------------------------- |
| `authVerifier.tls.existingSecret`      | `tls.crt`, `tls.key`, `ca.crt` (`caKey`) |
| `authVerifier.tls.clientCaSecret`      | `ca.crt` (`clientCaKey`)      |
| `authVerifier.sessionJwt.existingSecret` | `tls.crt`, `tls.key` (EC P-256) |
| `authVerifier.certificateJwt.existingSecret` | `tls.crt`, `tls.key` (EC P-256) |
| `authVerifier.database.existingSecret` | `database-url`                |
| `authVerifier.sessionStore.existingSecret` | `session-store-url`       |
| `saml.existingSecret`                  | `tls.crt`, `tls.key` (RSA)    |

## Source files

- [`values.yaml`](values.yaml) — all configurable parameters and defaults
- [`templates/`](templates/) — Kubernetes resource templates
- [`Chart.yaml`](Chart.yaml) — chart metadata
