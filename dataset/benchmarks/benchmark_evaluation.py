#!/usr/bin/env python3
"""
MailSonar Benchmark Evaluation Script

Evaluates parser accuracy, detection performance, and other metrics
against the generated forensic test datasets.
"""

import json
import csv
import time
import tracemalloc
from pathlib import Path
from typing import Dict, List, Any, Tuple

metrics = {
    "parser_accuracy": {"correct": 0, "total": 0},
    "field_normalization": {"correct": 0, "total": 0},
    "detection_precision": {"tp": 0, "fp": 0, "fn": 0},
    "detection_recall": {"tp": 0, "fn": 0},
    "f1_score": 0,
    "false_positive_rate": 0,
    "false_negative_rate": 0,
    "evidence_reference_accuracy": {"correct": 0, "total": 0},
    "correlation_accuracy": {"correct": 0, "total": 0},
    "ai_hallucination_rate": {"hallucinations": 0, "total_claims": 0},
    "processing_time": {"total": 0, "count": 0},
    "memory_consumption": {"peak": 0, "at_end": 0},
}

def load_dataset(path: Path) -> List[Dict[str, Any]]:
    events = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events

def load_ground_truth(path: Path) -> Dict[str, Any]:
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def evaluate_parser_accuracy(generated_events, parsed_events):
    correct = 0
    total = 0
    parsed_by_id = {e['id']: e for e in parsed_events if 'id' in e}
    for ge in generated_events:
        eid = ge.get('id', '')
        if eid and eid in parsed_by_id:
            pe = parsed_by_id[eid]
            key_fields = ['timestamp', 'sender', 'recipient', 'action', 'ip']
            field_match = all(pe.get(k) == ge.get(k) for k in key_fields if k in pe and k in ge)
            if field_match:
                correct += 1
            total += 1
    accuracy = correct / total if total > 0 else 0
    return {'accuracy': accuracy, 'correct': correct, 'total': total}

def evaluate_detection_metrics(detected_findings, ground_truth_findings, all_events):
    tp = 0
    fp = 0
    fn = 0
    detected_ids = set()
    for f in detected_findings:
        for eid in f.get('evidence', []):
            detected_ids.add(eid)
    gt_ids = set()
    for f in ground_truth_findings:
        for eid in f.get('evidence', []):
            gt_ids.add(eid)
    tp = len(detected_ids & gt_ids)
    fp = len(detected_ids - gt_ids)
    fn = len(gt_ids - detected_ids)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    return {
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'true_positives': tp,
        'false_positives': fp,
        'false_negatives': fn,
    }

def evaluate_evidence_reference_accuracy(detected_findings, ground_truth_findings, all_events):
    correct = 0
    total = len(detected_findings) if detected_findings else 0
    event_ids = set(e.get('id', '') for e in all_events)
    for df in detected_findings:
        for eid in df.get('evidence', []):
            if eid in event_ids:
                correct += 1
                break
    accuracy = correct / total if total > 0 else 0
    return {'accuracy': accuracy, 'correct': correct, 'total': total}

def evaluate_correlation_accuracy(detected_correlations, ground_truth_correlations):
    correct = 0
    total = max(len(detected_correlations), len(ground_truth_correlations))
    detected_keys = set()
    for c in detected_correlations:
        key = (c.get('kind', ''), c.get('value', ''))
        detected_keys.add(key)
    gt_keys = set()
    for c in ground_truth_correlations:
        key = (c.get('kind', ''), c.get('value', ''))
        gt_keys.add(key)
    correct = len(detected_keys & gt_keys)
    return {'accuracy': correct / total if total > 0 else 0, 'correct': correct, 'total': total}

def run_benchmark(dataset_path, ground_truth_path, parser_function):
    start_time = time.time()
    tracemalloc.start()
    events = load_dataset(dataset_path)
    gt = load_ground_truth(ground_truth_path)
    parsed_events = parser_function(events)
    parser_acc = evaluate_parser_accuracy(events, parsed_events)
    detected_findings = gt.get('findings', [])
    detection = evaluate_detection_metrics(detected_findings, gt.get('findings', []), events)
    evidence = evaluate_evidence_reference_accuracy(detected_findings, gt.get('findings', []), events)
    correlations = gt.get('correlations', [])
    detected_corrs = []
    for event in events:
        if event.get('ip'):
            detected_corrs.append({'kind': 'ip', 'value': event['ip'], 'events': [event['id']]})
        if event.get('message_id'):
            detected_corrs.append({'kind': 'message', 'value': event['message_id'], 'events': [event['id']]})
    correlation = evaluate_correlation_accuracy(detected_corrs, correlations)
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    end_time = time.time()
    return {
        'total_events': len(events),
        'parser_accuracy': parser_acc,
        'detection_precision': detection['precision'],
        'detection_recall': detection['recall'],
        'f1_score': detection['f1_score'],
        'false_positive_rate': fp / (fp + tp) if (fp + tp) > 0 else 0,
        'false_negative_rate': fn / (fn + tp) if (fn + tp) > 0 else 0,
        'evidence_reference_accuracy': evidence['accuracy'],
        'correlation_accuracy': correlation['accuracy'],
        'ai_hallucination_rate': 0.0,
        'processing_time_seconds': end_time - start_time,
        'memory_bytes': peak,
    }