# rust:1.88.0-slim-bookworm pinned by manifest digest (retrieved 2026-11-23).
FROM rust@sha256:38bc5a86d998772d4aec2348656ed21438d20fcdce2795b56ca434cf21430d89

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential ca-certificates curl python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
COPY tests ./tests
COPY benches ./benches
COPY scripts ./scripts
COPY vectors ./vectors
COPY reproduce.sh README.md ./

RUN chmod +x reproduce.sh scripts/fetch-vectors.sh \
    && rustup component add rustfmt clippy \
    && rustup target add thumbv7em-none-eabihf

CMD ["./reproduce.sh"]
