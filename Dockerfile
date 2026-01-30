FROM rust:1.75-alpine AS builder

RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconfig

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && echo "pub fn dummy() {}" > src/lib.rs
RUN mkdir -p benches && echo "fn main() {}" > benches/scan_bench.rs
RUN cargo build --release --target x86_64-unknown-linux-musl || true
RUN rm -rf src benches

COPY src ./src
COPY benches ./benches
RUN touch src/main.rs src/lib.rs
RUN cargo build --release --target x86_64-unknown-linux-musl

FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="Velka"
LABEL org.opencontainers.image.description="The Code Sin Judge - Security Scanner"
LABEL org.opencontainers.image.version="1.2.0"
LABEL org.opencontainers.image.source="https://github.com/wesllen-lima/velka"

COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/velka /velka

USER nonroot:nonroot

ENTRYPOINT ["/velka"]
CMD ["scan", "."]
