"""
Dataset registry for IOC-extraction evaluation.

Provides a single `load_samples()` entry point so the obfuscation ablation and
the calibration study can run on any evaluation set — the small hand-built
control set or the larger real-world CTI-report datasets — without each caller
re-implementing schema handling.

All loaders return a uniform list of sample dicts:
    {"id": str, "text": str,
     "expected_iocs": [{"value": str, "type": str}, ...],
     "category": str}

Registered datasets
-------------------
  synthetic     — 122 hand-built control samples (GroundTruthDataset)
  real_world    — real CTI report excerpts
  real_world_v2 — fuller real CTI reports (larger, recommended)
  benchmark     — dense real reports (~70 IOCs/sample)
  otx           — AlienVault OTX pulses (raw_text / ground_truth schema)
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

DATASET_PATHS: Dict[str, str] = {
    "real_world":    "data/evaluation/real_world_dataset.json",
    "real_world_v2": "data/evaluation/new_real_world_dataset.json",
    "benchmark":     "data/evaluation/benchmark_dataset.json",
    "otx":           "data/evaluation/otx_benchmark.json",
}


# Different datasets label IOC types with different vocabularies; canonicalise
# them to the IOCType enum values the extractor emits.
_TYPE_ALIASES: Dict[str, str] = {
    "hash_md5": "md5", "hash_sha1": "sha1", "hash_sha256": "sha256",
    "filehash-md5": "md5", "filehash-sha1": "sha1", "filehash-sha256": "sha256",
    "ipv4": "ip", "ipv4addr": "ip", "ip-dst": "ip", "ip-src": "ip",
    "ipv6addr": "ipv6", "hostname": "domain", "url-path": "url",
}


def _canonical_type(t: str) -> str:
    """Map a dataset-specific IOC type label to the canonical type."""
    t = t.strip().lower()
    return _TYPE_ALIASES.get(t, t)


def available_datasets() -> List[str]:
    """Return the registered dataset names."""
    return ["synthetic"] + list(DATASET_PATHS)


def _normalize_sample(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Coerce one raw record into the uniform sample schema.

    Handles both the standard schema (`text` / `expected_iocs`) and the OTX
    schema (`raw_text` / `ground_truth`).
    """
    text = raw.get("text") or raw.get("raw_text") or ""
    expected_raw = raw.get("expected_iocs")
    if expected_raw is None:
        expected_raw = raw.get("ground_truth", [])

    expected = [
        {"value": e["value"], "type": _canonical_type(e["type"])}
        for e in expected_raw
        if isinstance(e, dict) and e.get("value") and e.get("type")
    ]
    return {
        "id": str(raw.get("id", "")),
        "text": text,
        "expected_iocs": expected,
        "category": raw.get("category", "true_positive"),
    }


def load_samples(name: str) -> List[Dict[str, Any]]:
    """
    Load an evaluation dataset by registered name or by file path.

    Args:
        name: a key in DATASET_PATHS, the literal "synthetic", or a JSON path.

    Returns:
        List of uniform sample dicts (see module docstring).
    """
    if name == "synthetic":
        from threat_intel_aggregator.evaluation.ground_truth import GroundTruthDataset
        return [
            {
                "id": s.id,
                "text": s.text,
                "expected_iocs": [e.to_dict() for e in s.expected_iocs],
                "category": s.category,
            }
            for s in GroundTruthDataset().samples
        ]

    path = DATASET_PATHS.get(name, name)
    with open(path) as f:
        data = json.load(f)
    rows = data if isinstance(data, list) else data.get("samples", [])
    samples = [_normalize_sample(r) for r in rows]
    logger.info(
        "Loaded dataset '%s': %d samples, %d expected IOCs",
        name, len(samples), sum(len(s["expected_iocs"]) for s in samples),
    )
    return samples
