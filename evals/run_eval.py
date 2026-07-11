"""
run_eval.py

Runs the full triage pipeline (agent_core.triage_finding) on all 20
labelled findings in eval_dataset.py, then scores the agent's predictions
against our ground-truth labels:

  - Severity accuracy (exact match against ground_truth_severity)
  - Per-class precision / recall / F1 for each severity level
  - "Within one level" accuracy (ordinal tolerance -- e.g. predicting HIGH
    when the answer is CRITICAL is a much smaller miss than predicting LOW)
  - Escalation accuracy (did the agent escalate exactly the findings a
    human reviewer would want escalated?)

Saves a full scorecard to eval/eval_results.json and prints a summary.
"""

import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanners"))

from agent_core import triage_finding
from finding_schema import Finding
from eval_dataset import EVAL_FINDINGS

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_INDEX = {s: i for i, s in enumerate(SEVERITY_ORDER)}


def _extract_prediction(triage_result):
    """
    Pulls the predicted severity out of a triage_finding() result by
    finding the classify_severity tool call (always the first call, but
    we search defensively rather than assume index 0).
    """
    for call in triage_result["tool_calls"]:
        if call["tool"] == "classify_severity":
            severity = str(call["result"].get("severity", "")).upper()
            return severity if severity in SEVERITY_INDEX else None
    return None


def _compute_metrics(predictions):
    """
    predictions: list of dicts with keys:
        ground_truth, predicted, escalated, ground_truth_should_escalate

    Returns a metrics dict: overall accuracy, within-one-level accuracy,
    per-class precision/recall/F1, escalation accuracy.
    """
    total = len(predictions)
    exact_matches = sum(1 for p in predictions if p["predicted"] == p["ground_truth"])

    within_one = 0
    for p in predictions:
        if p["predicted"] is None:
            continue
        gt_idx = SEVERITY_INDEX[p["ground_truth"]]
        pred_idx = SEVERITY_INDEX[p["predicted"]]
        if abs(gt_idx - pred_idx) <= 1:
            within_one += 1

    escalation_matches = sum(
        1 for p in predictions if p["escalated"] == p["ground_truth_should_escalate"]
    )

    # Per-class precision/recall/F1 (one-vs-rest, computed manually --
    # avoids adding a scikit-learn dependency for 4 simple classes).
    per_class = {}
    for cls in SEVERITY_ORDER:
        tp = sum(1 for p in predictions if p["predicted"] == cls and p["ground_truth"] == cls)
        fp = sum(1 for p in predictions if p["predicted"] == cls and p["ground_truth"] != cls)
        fn = sum(1 for p in predictions if p["predicted"] != cls and p["ground_truth"] == cls)

        precision = tp / (tp + fp) if (tp + fp) > 0 else None
        recall = tp / (tp + fn) if (tp + fn) > 0 else None
        f1 = (
            2 * precision * recall / (precision + recall)
            if precision is not None and recall is not None and (precision + recall) > 0
            else None
        )

        per_class[cls] = {
            "precision": round(precision, 3) if precision is not None else None,
            "recall": round(recall, 3) if recall is not None else None,
            "f1": round(f1, 3) if f1 is not None else None,
            "support": tp + fn,  # number of ground-truth instances of this class
        }

    return {
        "total_findings": total,
        "exact_match_accuracy": round(exact_matches / total, 3),
        "within_one_level_accuracy": round(within_one / total, 3),
        "escalation_accuracy": round(escalation_matches / total, 3),
        "per_class_metrics": per_class,
    }


def run_eval():
    predictions = []

    for i, raw in enumerate(EVAL_FINDINGS, start=1):
        finding = Finding(
            id=raw["id"], source=raw["source"], title=raw["title"],
            description=raw["description"], file_path=raw["file_path"],
            line_number=raw["line_number"], raw_severity=raw["raw_severity"],
            cwe_id=raw["cwe_id"], code_snippet=raw["code_snippet"],
        )

        print(f"[{i}/{len(EVAL_FINDINGS)}] Evaluating {finding.id}: {finding.title}...")

        try:
            triage_result = triage_finding(finding)
            predicted = _extract_prediction(triage_result)
            escalated = triage_result["escalated"]
        except Exception as e:
            print(f"  -> ERROR: {e}")
            predicted = None
            escalated = True  # treat pipeline failures as a (safe) escalation

        ground_truth = raw["ground_truth_severity"]
        match_str = "MATCH" if predicted == ground_truth else "MISS"
        print(f"  -> predicted={predicted}, ground_truth={ground_truth} [{match_str}], escalated={escalated}")

        predictions.append({
            "finding_id": finding.id,
            "title": finding.title,
            "predicted": predicted,
            "ground_truth": ground_truth,
            "escalated": escalated,
            "ground_truth_should_escalate": raw["ground_truth_should_escalate"],
        })

    metrics = _compute_metrics(predictions)

    output = {
        "metrics": metrics,
        "predictions": predictions,
    }

    output_path = os.path.join(os.path.dirname(__file__), "..", "reports", "eval_results.json")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)

    print("\n" + "=" * 60)
    print("EVAL SCORECARD")
    print("=" * 60)
    print(f"Total findings evaluated:      {metrics['total_findings']}")
    print(f"Exact-match severity accuracy: {metrics['exact_match_accuracy']:.1%}")
    print(f"Within-one-level accuracy:     {metrics['within_one_level_accuracy']:.1%}")
    print(f"Escalation accuracy:           {metrics['escalation_accuracy']:.1%}")
    print("\nPer-class metrics:")
    print(f"{'Class':<10}{'Precision':<12}{'Recall':<12}{'F1':<12}{'Support':<8}")
    for cls, m in metrics["per_class_metrics"].items():
        p = f"{m['precision']:.3f}" if m["precision"] is not None else "n/a"
        r = f"{m['recall']:.3f}" if m["recall"] is not None else "n/a"
        f1 = f"{m['f1']:.3f}" if m["f1"] is not None else "n/a"
        print(f"{cls:<10}{p:<12}{r:<12}{f1:<12}{m['support']:<8}")
    print(f"\nFull results saved to {output_path}")

    return output


if __name__ == "__main__":
    run_eval()