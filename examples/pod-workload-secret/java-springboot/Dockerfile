# --- build stage ---
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /build
COPY pom.xml .
# Cache dependencies first.
RUN mvn -q -e -B dependency:go-offline
COPY src ./src
RUN mvn -q -B -DskipTests package

# --- run stage ---
# Pin a digest in your own build so the running image matches the digest you
# approve in the portal (Layer 4): eclipse-temurin:21-jre@sha256:...
FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /build/target/pod-workload-secret-springboot-*.jar app.jar

# Run as non-root; the decrypted credential lives only in this process's memory.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app
USER 10001

ENTRYPOINT ["java", "-jar", "/app/app.jar"]
