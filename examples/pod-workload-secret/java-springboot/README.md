# pod-workload-secret — Java / Spring Boot

A Spring Boot service that **decrypts its database (and Redis) credentials from ASTIS
at startup, then hands them to the normal connection factories** — with no change to
the factory code, and **no ASTIS code in the app**. See the
[use-case overview](../README.md) for the concept, the four-layer model, and the threat
model. This page is the Java specifics.

## The integration is one dependency

All the ASTIS logic lives in **`astis-spring-boot-starter`** (from the
`astis-sdk` repo — see [Build](#build) for installing it until it lands on Maven
Central). This app just adds it and declares which property comes from
which sealed envelope — it ships none of its own crypto or `EnvironmentPostProcessor`
code:

```xml
<dependency>
  <groupId>io.astis</groupId>
  <artifactId>astis-spring-boot-starter</artifactId>
  <version>0.1.0</version>
</dependency>
```

The starter registers a single `AstisEnvironmentPostProcessor` (via its own
`spring.factories`) that runs **before the application context exists** — earlier than
any `@Bean`, including the DataSource and `RedisConnectionFactory`:

```
ApplicationEnvironmentPrepared
  → AstisEnvironmentPostProcessor (from the starter)
        for each mapping: RFC-020 unwrap → plaintext → inject as a Spring property
        e.g. spring.datasource.password
  → ApplicationContext refresh
  → DataSource / Redis autoconfiguration reads the ALREADY-DECRYPTED property
```

So Spring's own autoconfiguration wires Hikari / Lettuce with the decrypted password
transparently. The plaintext exists only in the pod's RAM; it is never logged (only a
sha256 prefix), and the ASTIS edge — and whatever delivered the ciphertext — only ever
see HPKE-sealed blobs.

## Configure which property comes from which envelope

This example uses **Channel A (mount mapping)**: each property is fed from a sealed
envelope mounted into the pod (a k8s Secret). See
[`application.yaml`](./src/main/resources/application.yaml):

```yaml
astis:
  api-url: https://api.astis.io
  cluster-id: prod-eu        # must match the API key's workload binding
  service-account: hr-portal
  secrets:
    enabled: true
    mappings:
      - property: spring.datasource.username
        envelope-path: /etc/astis-sealed/db-user
      - property: spring.datasource.password
        envelope-path: /etc/astis-sealed/db-password
```

The starter also supports **Channel B (inline `{astis}` marker)** — opt-in and scoped —
for ciphertext served inline by Spring Cloud Config / a Vault-backed config server
(`spring.datasource.password: "{astis}ASTIS:v2:…"`). The config courier holds only
ciphertext; decryption still happens pod-local. See the
[starter README](https://github.com/astis-io/astis-sdk/tree/main/integrations/spring-boot-starter)
for the full config reference and why this beats native `{cipher}` (where the config
server holds the key).

## Build

The starter and its Java SDK are consumed as normal Maven artifacts. Until they are
published to a shared registry, install them once from the `astis-sdk` repo:

```bash
# in astis-sdk/
( cd sdks/java && mvn -q install -DskipTests )
( cd integrations/spring-boot-starter && mvn -q install -DskipTests )
```

Then build this example:

```bash
mvn -q -DskipTests package          # -> target/pod-workload-secret-springboot-0.1.0.jar
```

The cross-language known-answer test (Python seals, Java/BouncyCastle opens) lives with
the SDK in `astis-sdk/sdks/java`; it is not duplicated here.

## Build the image & deploy

```bash
docker build -t registry.example.com/hr-portal:1.0 .
docker push registry.example.com/hr-portal:1.0   # approve the @sha256:... digest in the portal (Layer 4)
```

Then deploy with the shared manifests in [`../base/`](../base/). At runtime:

```bash
kubectl -n hr-portal-demo port-forward deploy/hr-portal 8080:8080
curl localhost:8080/healthz
# { "status":"ok",
#   "secrets":{ "spring.datasource.password":{ "loaded":true, "sha256":"0e965c33ba2d", "length":8 }, ... },
#   "database":{ "connected":true, "current_user":"postgres", "version":"PostgreSQL 15.18 …" } }
```

`/healthz` proves the credential is live where the connection factories read it — and
that a real DB connection was opened with it — while reporting only a sha256 prefix,
never the plaintext.

> **Live-validated on an internal Kubernetes cluster.** This exact app (starter-based)
> decrypted its PostgreSQL credentials at startup and opened a real connection; the pod
> log shows `io.astis.spring.AstisEnvironmentPostProcessor` (the starter), `env | grep
> passw` is empty, and the mounted file is `ASTIS:v2:` ciphertext.

## Files

| File | Role |
|---|---|
| `pom.xml` | adds `io.astis:astis-spring-boot-starter` — the only ASTIS dependency |
| `application.yaml` | maps Spring properties → sealed envelopes (Channel A) |
| `WorkloadSecretApplication.java` | plain `@SpringBootApplication` — no ASTIS code |
| `DbProbe.java` | opens a real PostgreSQL connection with the decrypted creds at startup |
| `SecretController.java` | `/healthz` — proves properties + DB are live (sha256 only) |

All decryption code is in the starter (`astis-sdk`), not here — which is the
point: integrating ASTIS is adding a dependency and mapping a few properties.
