#!/usr/bin/env python3
"""
MobSF Findings Correlator

Correlates MobSF automated findings with manual analysis results.
"""

import json
from typing import List, Dict, Optional


class FindingCorrelator:
    """Correlates MobSF findings with manual findings."""

    def __init__(self, manual_findings: List[Dict], mobsf_findings: List[Dict]):
        self.manual_findings = manual_findings
        self.mobsf_findings = mobsf_findings

    def correlate(self) -> List[Dict]:
        merged = []

        for manual in self.manual_findings:
            manual["source"] = "manual"
            manual["mobsf_correlated"] = False
            manual["mobsf_id"] = None
            merged.append(manual)

        for mobsf in self.mobsf_findings:
            correlation = self._find_correlation(mobsf)

            if correlation:
                for finding in merged:
                    if finding["id"] == correlation["id"]:
                        finding["mobsf_correlated"] = True
                        finding["mobsf_id"] = mobsf.get("id")
                        finding["automated_evidence"] = mobsf.get("evidence")
                        break
            else:
                mobsf["source"] = "mobsf"
                mobsf["confidence"] = "Automated Detection"
                mobsf["needs_verification"] = True
                merged.append(mobsf)

        return merged

    def _find_correlation(self, mobsf_finding: Dict) -> Optional[Dict]:
        if "cwe_id" in mobsf_finding:
            for manual in self.manual_findings:
                if manual.get("cwe") == mobsf_finding["cwe_id"]:
                    return manual

        mobsf_title = mobsf_finding.get("title", "").lower()
        for manual in self.manual_findings:
            manual_title = manual.get("title", "").lower()
            if self._similar_strings(mobsf_title, manual_title):
                return manual

        if "file_path" in mobsf_finding:
            for manual in self.manual_findings:
                if manual.get("file") == mobsf_finding["file_path"]:
                    return manual

        return None

    def _similar_strings(self, s1: str, s2: str, threshold: float = 0.7) -> bool:
        words1 = set(s1.split())
        words2 = set(s2.split())

        if not words1 or not words2:
            return False

        intersection = len(words1.intersection(words2))
        union = len(words1.union(words2))

        return (intersection / union) >= threshold


if __name__ == "__main__":
    manual = [
        {
            "id": "FIND-001",
            "title": "SQL Injection in User Query",
            "cwe": "CWE-89",
            "file": "ViewController.swift",
            "confidence": "Confirmed",
        }
    ]

    mobsf = [
        {
            "id": "MOBSF-001",
            "title": "SQL Injection",
            "cwe_id": "CWE-89",
            "file_path": "ViewController.swift",
        }
    ]

    correlator = FindingCorrelator(manual, mobsf)
    merged = correlator.correlate()

    print(json.dumps(merged, indent=2))
