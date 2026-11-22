#!/usr/bin/env python3
"""Draw a dependency-free SVG bar chart from results/benchmarks.csv."""

import csv
import html
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CSV_PATH = ROOT / "results" / "benchmarks.csv"
SVG_PATH = ROOT / "results" / "benchmarks.svg"

WIDTH = 1180
ROW_HEIGHT = 26
TOP = 56
LEFT = 300
BAR_WIDTH = 760


def main():
    with open(CSV_PATH, newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise SystemExit("no benchmark rows")

    values = []
    for row in rows:
        parts = row["benchmark"].rsplit("_", 2)
        if len(parts) != 3:
            continue
        label = "/".join(parts)
        values.append((label, float(row["mean_ns"]) / 1000.0))
    maximum = max(value for _, value in values) or 1.0

    height = TOP + ROW_HEIGHT * len(values) + 40
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{height}" '
        f'viewBox="0 0 {WIDTH} {height}" font-family="system-ui, sans-serif" font-size="12">',
        '<rect width="100%" height="100%" fill="white"/>',
        '<text x="20" y="26" font-size="18" font-weight="600">ML-KEM benchmark mean latency (us)</text>',
        '<text x="20" y="44" fill="#555">Ours vs RustCrypto ml-kem 0.3.4; lower is better.</text>',
    ]
    for index, (name, value) in enumerate(values):
        y = TOP + index * ROW_HEIGHT
        width = max(1.0, value / maximum * BAR_WIDTH)
        color = "#2563eb" if name.endswith("/ours") else "#94a3b8"
        lines.append(
            f'<text x="20" y="{y + 15}">{html.escape(name)}</text>'
        )
        lines.append(
            f'<rect x="{LEFT}" y="{y + 3}" width="{width:.2f}" height="18" fill="{color}"/>'
        )
        lines.append(
            f'<text x="{LEFT + width + 8:.2f}" y="{y + 16}">{value:.2f}</text>'
        )
    lines.append("</svg>")
    SVG_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(SVG_PATH)


if __name__ == "__main__":
    main()
