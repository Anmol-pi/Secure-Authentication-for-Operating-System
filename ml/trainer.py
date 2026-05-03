#!/usr/bin/env python3
"""
LinuxAuthGuard - Model Trainer
Loads labelled data, extracts features, trains the Random Forest,
and saves the model. Can run as a one-shot or periodic service.
"""

from __future__ import annotations

import csv
import logging
import os
import sqlite3
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("linuxauthguard.ml.trainer")

SEED_CSV    = Path(__file__).parent / "seed_dataset.csv"
SUDO_DB     = "/var/lib/linuxauthguard/sudo_log.db"
ACCESS_DB   = "/var/lib/linuxauthguard/access_log.db"
RETRAIN_INTERVAL = 86400  # 24 hours


def _load_access_stats(db_path: str) -> Dict[str, Dict[str, int]]:
    """
    Load per-file access statistics from the sudo_log database.
    Returns: {path: {sudo_count, normal_count, unique_sudo_users, last_sudo_timestamp}}
    """
    stats: Dict[str, Dict[str, int]] = {}
    if not Path(db_path).exists():
        return stats
    try:
        con = sqlite3.connect(db_path, timeout=5)
        con.row_factory = sqlite3.Row
        rows = con.execute(
            """
            SELECT
                file_path,
                SUM(CASE WHEN via_sudo = 1 THEN 1 ELSE 0 END) AS sudo_count,
                SUM(CASE WHEN via_sudo = 0 THEN 1 ELSE 0 END) AS normal_count,
                COUNT(DISTINCT CASE WHEN via_sudo = 1 THEN username END) AS unique_sudo_users,
                MAX(CASE WHEN via_sudo = 1 THEN timestamp END) AS last_sudo_timestamp
            FROM sudo_events
            GROUP BY file_path
            """
        ).fetchall()
        for row in rows:
            stats[row["file_path"]] = {
                "sudo_count":          row["sudo_count"] or 0,
                "normal_count":        row["normal_count"] or 0,
                "unique_sudo_users":   row["unique_sudo_users"] or 0,
                "last_sudo_timestamp": row["last_sudo_timestamp"] or 0,
            }
        con.close()
    except Exception as e:
        logger.warning("Could not load access stats: %s", e)
    return stats


def _load_seed_dataset(csv_path: Path) -> Tuple[List[List[float]], List[int]]:
    """
    Load the seed labelled dataset from CSV.
    Expected columns: label, path, [feature cols...]
    Returns (X, y).
    """
    if not csv_path.exists():
        logger.warning("Seed dataset not found at %s", csv_path)
        return [], []

    X: List[List[float]] = []
    y: List[int] = []

    # Import feature extractor lazily
    from feature_extractor import extract, FEATURE_NAMES

    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row_num, row in enumerate(reader, 1):
            try:
                label = int(row.get("label", "0"))
                file_path = row.get("path", "")

                if not file_path:
                    continue

                # Check if pre-computed features are in the CSV
                precomputed = []
                for fname in FEATURE_NAMES:
                    if fname in row and row[fname] != "":
                        precomputed.append(float(row[fname]))

                if len(precomputed) == len(FEATURE_NAMES):
                    # Use pre-computed features
                    X.append(precomputed)
                else:
                    # Extract features from the file path
                    features, _ = extract(file_path)
                    X.append(features)

                y.append(label)
            except (ValueError, KeyError) as e:
                logger.debug("Skipping CSV row %d: %s", row_num, e)

    logger.info("Loaded %d samples from seed dataset", len(X))
    return X, y


def _load_observed_data(
    access_stats: Dict[str, Dict[str, int]],
    min_accesses: int = 5,
) -> Tuple[List[List[float]], List[int]]:
    """
    Generate training samples from observed access patterns.
    Files with high sudo ratio are auto-labelled as sensitive.
    """
    from feature_extractor import extract

    X: List[List[float]] = []
    y: List[int] = []

    for file_path, stats in access_stats.items():
        total = stats["sudo_count"] + stats["normal_count"]
        if total < min_accesses:
            continue

        sudo_ratio = stats["sudo_count"] / total
        # Heuristic: >60% sudo access → label sensitive
        label = 1 if sudo_ratio >= 0.60 else 0

        try:
            features, _ = extract(file_path, access_stats=stats)
            X.append(features)
            y.append(label)
        except Exception as e:
            logger.debug("Feature extraction failed for %s: %s", file_path, e)

    logger.info("Generated %d samples from observed access data", len(X))
    return X, y


def train_model(
    classifier: object,
    use_seed: bool = True,
    use_observed: bool = True,
) -> Dict[str, object]:
    """
    Full training pipeline. Returns metrics dict.
    """
    X_combined: List[List[float]] = []
    y_combined: List[int] = []

    if use_seed:
        X_seed, y_seed = _load_seed_dataset(SEED_CSV)
        X_combined.extend(X_seed)
        y_combined.extend(y_seed)

    if use_observed:
        access_stats = _load_access_stats(SUDO_DB)
        X_obs, y_obs = _load_observed_data(access_stats)
        X_combined.extend(X_obs)
        y_combined.extend(y_obs)

    if not X_combined:
        logger.warning("No training data available")
        return {"error": "no_data"}

    logger.info(
        "Training on %d samples (%d positive, %d negative)",
        len(X_combined),
        sum(y_combined),
        len(y_combined) - sum(y_combined),
    )

    from feature_extractor import FEATURE_NAMES
    metrics = classifier.train(X_combined, y_combined, feature_names=FEATURE_NAMES)
    classifier.save()
    return metrics


def run_periodic_trainer(
    classifier: object,
    interval: int = RETRAIN_INTERVAL,
) -> None:
    """Run the retraining loop. Blocks forever (call from a thread)."""
    logger.info(
        "Periodic trainer started (interval=%d seconds / %.1f hours)",
        interval,
        interval / 3600,
    )
    while True:
        logger.info("Starting scheduled model retraining")
        try:
            metrics = train_model(classifier)
            logger.info("Retraining complete: %s", metrics)
        except Exception as e:
            logger.exception("Retraining failed: %s", e)
        logger.info("Next retraining in %d seconds", interval)
        time.sleep(interval)


def main() -> int:
    """One-shot training run (for cron / manual invocation)."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    from classifier import SensitivityClassifier

    clf = SensitivityClassifier()
    clf.load()  # Load existing model (we'll overwrite it)

    logger.info("Starting one-shot training run")
    metrics = train_model(clf)

    if "error" in metrics:
        logger.error("Training failed: %s", metrics["error"])
        return 1

    logger.info("Training complete. Metrics: %s", metrics)

    # Print feature importances
    importance = clf.get_feature_importance()
    if importance:
        logger.info("Top feature importances:")
        for name, score in sorted(importance.items(), key=lambda kv: -kv[1])[:10]:
            logger.info("  %-35s %.4f", name, score)

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
