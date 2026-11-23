#!/usr/bin/env bash
# Reproduce every test and benchmark in the README, inside or outside Docker.
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p results
rm -f results/dudect-*.csv results/dudect-*.txt

echo "== ACVP vectors =="
./scripts/fetch-vectors.sh
(cd vectors && sha256sum --check SHA256SUMS)

echo "== format, lint, no_std build =="
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --release --target thumbv7em-none-eabihf -- -D warnings
cargo build --release --target thumbv7em-none-eabihf

if command -v python3 >/dev/null 2>&1; then
    PYTHON=python3
else
    PYTHON=python
fi

echo "== correctness =="
cargo test --release --lib
cargo test --release --test crosscheck
cargo test --release --test properties
cargo test --release --features acvp --test acvp -- --nocapture

echo "== environment =="
{
    echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "rustc: $(rustc --version)"
    echo "cargo: $(cargo --version)"
    echo "uname: $(uname -a)"
    if [ -r /proc/cpuinfo ]; then
        echo "cpu: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//')"
    fi
    if command -v nproc >/dev/null 2>&1; then
        echo "nproc: $(nproc)"
    fi
} | tee results/environment.txt

echo "== dudect =="
DUDECT_SAMPLES="${DUDECT_SAMPLES:-1000000}" \
    cargo bench --bench dudect -- --out results/dudect-decaps.csv --filter decaps \
    | tee results/dudect-decaps.txt
DUDECT_SAMPLES="${DUDECT_SAMPLES:-1000000}" \
    cargo bench --bench dudect -- --out results/dudect-compress.csv --filter compress \
    | tee results/dudect-compress.txt

echo "== criterion =="
cargo bench --bench kem
"$PYTHON" scripts/bench_to_csv.py
"$PYTHON" scripts/plot_bench.py

echo "== done =="
echo "Results are in results/."
