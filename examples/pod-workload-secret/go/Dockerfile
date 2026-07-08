# --- build stage ---
FROM golang:1.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Static binary (lib/pq is pure Go) so it runs on a minimal base.
RUN CGO_ENABLED=0 go build -o /out/app .

# --- run stage ---
# Pin a digest in your own build so the running image matches the digest you approve in
# the portal (Layer 4): gcr.io/distroless/static@sha256:...
FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/app /app
USER 65532:65532
ENTRYPOINT ["/app"]
