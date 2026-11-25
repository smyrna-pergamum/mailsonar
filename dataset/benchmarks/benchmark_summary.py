#!/usr/bin/env python3
"""
MailSonar Benchmark Summary Report

Generated report for dataset evaluation results.

"""

import json
import sys
from pathlib import Path

def load_result(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def generate_summary(results):
    if not results:
        print('No benchmark results found.', file=sys.stderr)
        return {}
    agg = {
        "datasets_evaluated": len(results),
        "average_parser_accuracy": sum(r.get("parser_accuracy", {"accuracy": 0}).get("accuracy", 0) for r in results) / len(results),
        "average_detection_precision": sum(r.get("detection_precision", 0) for r in results) / len(results),
        "average_detection_recall": sum(r.get("detection_recall", 0) for r in results) / len(results),
        "average_f1_score": sum(r.get("f1_score", 0) for r in results) / len(results),
        "average_false_positive_rate": sum(r.get("false_positive_rate", 0) for r in results) / len(results),
        "average_false_negative_rate": sum(r.get("false_negative_rate", 0) for r in results) / len(results),
        "average_evidence_reference_accuracy": sum(r.get("evidence_reference_accuracy", {"accuracy": 0}).get("accuracy", 0) for r in results) / len(results),
        "average_correlation_accuracy": sum(r.get("correlation_accuracy", 0) for r in results) / len(results),
        "average_ai_hallucination_rate": sum(r.get("ai_hallucination_rate", 0) for r in results) / len(results),
        "average_processing_time": sum(r.get("processing_time_seconds", 0) for r in results) / len(results),
        "average_memory_mb": sum(r.get("memory_consumption", {"peak": 0}).get("peak", 0) / 1048576 for r in results) / len(results),
    }
    return agg

if __name__ == '__main__':
    dataset_dir = Path('dataset')
    results = []
    for size_name in ['10k', '100k', 'million']:
        result_path = Path('benchmark-results-%s.json' % size_name)
        if result_path.exists():
            results.append(load_result(result_path)),
    summary = generate_summary(results),
    if summary:
        print('MailSonar Benchmark Summary'),
        print('========================='),
        print('Datasets evaluated: %d' % summary['datasets_evaluated']),
        print('Average parser accuracy: %.2%%' % summary['average_parser_accuracy']),
        print('Average detection precision: %.2%%' % summary['average_detection_precision']),
        print('Average detection recall: %.2%%' % summary['average_detection_recall']),
        print('Average F1 score: %.2%%' % summary['average_f1_score']),
        print('Average false positive rate: %.2%%' % summary['average_false_positive_rate']),
        print('Average false negative rate: %.2%%' % summary['average_false_negative_rate']),
        print('Average evidence reference accuracy: %.2%%' % summary['average_evidence_reference_accuracy']),
        print('Average correlation accuracy: %.2%%' % summary['average_correlation_accuracy']),
        print('Average AI hallucination rate: %.2%%' % summary['average_ai_hallucination_rate']),
        print('Average processing time: %.2fs' % summary['average_processing_time']),
        print('Average memory consumption: %.2f MB' % summary['average_memory_mb']),