#!/usr/bin/env python3
"""Verify the generated dataset."""
import json
from pathlib import Path

print("=" * 60)
print("MailSonar Dataset Verification")
print("=" * 60)

# Check 10k ground truth
gt_10k = Path("dataset/ground_truth/ground-truth-10k.json").read_text()
data = json.loads(gt_10k)
print("\n1. 10k Dataset:")
print("   Events: %d" % len(data["events"]))
print("   Findings: %d" % len(data["findings"]))
print("   Correlations: %d" % len(data["correlations"]))
print("   Event types: %s" % str(list(set(e.get("source_dataset", "unknown") for e in data["events"]))))

# Check 100k ground truth
gt_100k = Path("dataset/ground_truth/ground-truth-100k.json").read_text()
data100k = json.loads(gt_100k)
print("\n2. 100k Dataset:")
print("   Events: %d" % len(data100k["events"]))
print("   Findings: %d" % len(data100k["findings"]))
print("   Correlations: %d" % len(data100k["correlations"]))

# Check million summary
gt_million = Path("dataset/ground_truth/ground-truth-million-summary.json").read_text()
data_million = json.loads(gt_million)
print("\n3. Million Dataset (summary):")
print("   Events (first 10K): %d" % len(data_million["events"]))
print("   Findings: %d" % len(data_million["findings"]))
print("   Correlations: %d" % len(data_million["correlations"]))

# Check format files
formats_dir = Path("dataset/formats")
csv_files = sorted(formats_dir.glob("*.csv"))
jsonl_files = sorted(formats_dir.glob("*.jsonl"))
xml_files = sorted(formats_dir.glob("*.xml"))
txt_files = sorted(formats_dir.glob("*.txt"))
log_files = sorted(formats_dir.glob("*.log"))
eml_files = sorted(formats_dir.glob("*.eml_manifest.json"))
msg_files = sorted(formats_dir.glob("*.msg_manifest.json"))
evtx_files = sorted(formats_dir.glob("*.evtx_manifest.json"))
zip_files = sorted(formats_dir.glob("*.zip"))
gz_files = sorted(formats_dir.glob("*.gz"))
xlsx_files = sorted(formats_dir.glob("*.xlsx"))

print("\n4. Format Files:")
all_format_files = csv_files + jsonl_files + xml_files + txt_files + log_files + eml_files + msg_files + evtx_files + zip_files + gz_files + xlsx_files
for f in all_format_files:
    print("   - %s (%d bytes)" % (f.name, f.stat().st_size))

# Check metadata
metadata_dir = Path("dataset/metadata")
print("\n5. Metadata Files:")
for f in sorted(metadata_dir.glob("*.json")):
    m = json.loads(f.read_text())
    print("   - %s: %d events, %d findings" % (f.name, m["total_events"], m["findings_count"]))

# Check benchmarks
benchmarks_dir = Path("dataset/benchmarks")
print("\n6. Benchmark Scripts:")
for f in sorted(benchmarks_dir.glob("*.py")):
    print("   - %s" % f.name)

print("\n" + "=" * 60)
print("Verification complete!")
print("=" * 60)