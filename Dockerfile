FROM scratch AS cargo-vendor

FROM rust:1.100-trixie AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations
COPY templates ./templates
RUN --mount=type=bind,from=cargo-vendor,target=/cargo-sources \
    if [ -d /cargo-sources/vendor ]; then \
        cargo --config 'source.crates-io.replace-with="vendored"' \
              --config 'source.vendored.directory="/cargo-sources/vendor"' build --locked --offline --release; \
    else \
        cargo build --locked --release; \
    fi

FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/target/release/tincan /usr/local/bin/tincan
ENV TINCAN_BIND=0.0.0.0:3000
EXPOSE 3000
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/tincan"]
