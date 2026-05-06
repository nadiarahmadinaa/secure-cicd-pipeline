#!/usr/bin/env python3
"""
Convert a ZAP JSON report (report_json.json) to SARIF 2.1.0 format
for upload to the GitHub Security tab.

Usage: python3 zap-to-sarif.py <zap-report.json> <output.sarif>
"""

import json
import sys
import uuid
from datetime import datetime, timezone

ZAP_RISK_TO_SARIF_LEVEL = {
    "3": "error",    # High
    "2": "warning",  # Medium
    "1": "note",     # Low
    "0": "note",     # Informational
}

ZAP_RISK_TO_SECURITY_SEVERITY = {
    "3": "9.0",  # High → CVSS ~9.0
    "2": "6.5",  # Medium → CVSS ~6.5
    "1": "3.1",  # Low → CVSS ~3.1
    "0": "0.0",  # Info
}


def build_sarif(zap_report: dict) -> dict:
    rules = {}
    results = []

    for site in zap_report.get("site", []):
        for alert in site.get("alerts", []):
            plugin_id = str(alert.get("pluginid", alert.get("alertRef", "unknown")))
            risk_code = str(alert.get("riskcode", "0"))
            cwe_id = str(alert.get("cweid", ""))

            # Deduplicate rules by plugin ID
            if plugin_id not in rules:
                rule = {
                    "id": f"ZAP-{plugin_id}",
                    "name": _to_pascal_case(alert.get("name", f"ZAP-{plugin_id}")),
                    "shortDescription": {"text": alert.get("name", f"ZAP Alert {plugin_id}")},
                    "fullDescription": {"text": _strip_html(alert.get("desc", ""))},
                    "help": {
                        "text": _strip_html(alert.get("solution", "See ZAP documentation.")),
                        "markdown": (
                            f"**Solution:** {_strip_html(alert.get('solution', ''))}\n\n"
                            f"**Reference:** {alert.get('reference', '')}"
                        ),
                    },
                    "properties": {
                        "tags": ["security"],
                        "security-severity": ZAP_RISK_TO_SECURITY_SEVERITY.get(risk_code, "0.0"),
                        "precision": "medium",
                    },
                    "defaultConfiguration": {
                        "level": ZAP_RISK_TO_SARIF_LEVEL.get(risk_code, "note"),
                    },
                }
                if cwe_id and cwe_id != "-1":
                    rule["relationships"] = [
                        {
                            "target": {
                                "id": f"CWE-{cwe_id}",
                                "toolComponent": {"name": "CWE"},
                            },
                            "kinds": ["superset"],
                        }
                    ]
                rules[plugin_id] = rule

            for instance in alert.get("instances", [{"uri": site.get("@name", ""), "method": "GET", "evidence": ""}]):
                uri = instance.get("uri", "")
                result = {
                    "ruleId": f"ZAP-{plugin_id}",
                    "level": ZAP_RISK_TO_SARIF_LEVEL.get(risk_code, "note"),
                    "message": {
                        "text": (
                            f"{alert.get('name', 'ZAP Alert')}: {_strip_html(alert.get('desc', ''))}"
                            + (f"\n\nEvidence: {instance.get('evidence', '')}" if instance.get("evidence") else "")
                        )
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": uri,
                                    "uriBaseId": "%SRCROOT%",
                                },
                            },
                            "logicalLocations": [
                                {
                                    "name": f"{instance.get('method', 'GET')} {uri}",
                                    "kind": "function",
                                }
                            ],
                        }
                    ],
                    "partialFingerprints": {
                        "primaryLocationLineHash": str(
                            hash(f"{plugin_id}:{uri}:{instance.get('method', '')}")
                        ),
                    },
                    "properties": {
                        "wasc-id": str(alert.get("wascid", "")),
                        "confidence": str(alert.get("confidence", "")),
                    },
                }
                results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "OWASP ZAP",
                        "version": zap_report.get("@version", "unknown"),
                        "informationUri": "https://www.zaproxy.org/",
                        "semanticVersion": zap_report.get("@version", "0.0.0"),
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "commandLine": "zap-baseline.py",
                        "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                    }
                ],
                "originalUriBaseIds": {
                    "%SRCROOT%": {"uri": "file:///"},
                },
                "properties": {
                    "scanDate": zap_report.get("@generated", ""),
                    "reportId": str(uuid.uuid4()),
                },
            }
        ],
    }
    return sarif


def _strip_html(text: str) -> str:
    """Remove HTML tags from ZAP description strings."""
    import re
    clean = re.sub(r"<[^>]+>", "", text or "")
    return " ".join(clean.split())


def _to_pascal_case(text: str) -> str:
    return "".join(word.capitalize() for word in text.replace("-", " ").replace("_", " ").split())


def main() -> None:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <zap-report.json> <output.sarif>", file=sys.stderr)
        sys.exit(1)

    input_path, output_path = sys.argv[1], sys.argv[2]

    try:
        with open(input_path) as f:
            zap_report = json.load(f)
    except FileNotFoundError:
        print(f"Error: ZAP report not found: {input_path}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error parsing ZAP report: {e}", file=sys.stderr)
        sys.exit(1)

    sarif = build_sarif(zap_report)

    with open(output_path, "w") as f:
        json.dump(sarif, f, indent=2)

    finding_count = len(sarif["runs"][0]["results"])
    print(f"Converted {finding_count} ZAP finding(s) → {output_path}")


if __name__ == "__main__":
    main()
