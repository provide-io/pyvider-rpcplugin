#!/usr/bin/env python3
"""Run COMPLETE security suite with provide-testkit."""
import sys
from pathlib import Path

# Ensure we can import from src
sys.path.insert(0, str(Path(__file__).parent / "src"))

def main():
    """Run all available security scanners."""
    from provide.testkit.quality.security import (
        SecurityScanner,  # Bandit
        PipAuditScanner,
        SemgrepScanner,
        GitLeaksScanner,
        TruffleHogScanner,
        SafetyScanner,
    )

    project_root = Path("/REDACTED_ABS_PATH")
    src_dir = project_root / "src"
    artifact_dir = project_root / ".provide/output/security"
    artifact_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print("COMPLETE SECURITY SCAN SUITE - ALL SCANNERS")
    print("=" * 80)

    scanners = [
        ("Bandit", SecurityScanner({
            "max_high_severity": 0,
            "max_medium_severity": 10,
            "min_score": 70.0,
            "verbosity": "quiet",
        }), src_dir),
        ("PipAudit", PipAuditScanner({
            "max_vulnerabilities": 5,
        }), project_root),
        ("Semgrep", SemgrepScanner({
            "config": ["auto"],
            "max_findings": 30,
        }), src_dir),
        ("GitLeaks", GitLeaksScanner({
            "max_secrets": 0,
        }), project_root),
        ("TruffleHog", TruffleHogScanner({
            "max_secrets": 0,
        }), project_root),
        ("Safety", SafetyScanner({
            "max_vulnerabilities": 5,
        }), project_root),
    ]

    results = []
    passed = 0
    failed = 0
    skipped = 0

    for i, (name, scanner, path) in enumerate(scanners, 1):
        print(f"\n[{i}/{len(scanners)}] Running {name}...")
        print("-" * 80)

        try:
            result = scanner.analyze(path, artifact_dir=artifact_dir)
            results.append((name, result))

            # Display results
            print(f"Score: {result.score:.1f}%")
            print(f"Status: {'✅ PASSED' if result.passed else '❌ FAILED'}")

            # Show details
            if name == "Bandit":
                print(f"Issues: {result.details['total_issues']} "
                      f"(HIGH: {result.details['severity_breakdown']['HIGH']}, "
                      f"MEDIUM: {result.details['severity_breakdown']['MEDIUM']}, "
                      f"LOW: {result.details['severity_breakdown']['LOW']})")
            elif name == "PipAudit":
                print(f"Vulnerabilities: {result.details['total_vulnerabilities']}")
            elif name == "Semgrep":
                print(f"Findings: {result.details['total_findings']}")
            elif name in ["GitLeaks", "TruffleHog"]:
                print(f"Secrets: {result.details['total_secrets']}")
                if result.details.get('verified_secrets', 0) > 0:
                    print(f"⚠️  VERIFIED (ACTIVE) SECRETS: {result.details['verified_secrets']}")
            elif name == "Safety":
                print(f"Vulnerabilities: {result.details['total_vulnerabilities']}")

            if result.passed:
                passed += 1
            else:
                failed += 1

        except Exception as e:
            print(f"⏭️  SKIPPED - {e}")
            skipped += 1

    # Summary
    print("\n" + "=" * 80)
    print("SECURITY SCAN SUMMARY")
    print("=" * 80)

    for name, result in results:
        status = "✅ PASSED" if result.passed else "❌ FAILED"
        print(f"{name:15s} Score: {result.score:6.1f}%   {status}")

    print("=" * 80)
    print(f"Passed:  {passed}/{len(scanners)}")
    print(f"Failed:  {failed}/{len(scanners)}")
    print(f"Skipped: {skipped}/{len(scanners)}")
    print("=" * 80)

    if failed == 0:
        print("✅ ALL AVAILABLE SECURITY SCANS PASSED!")
        return 0
    else:
        print(f"❌ {failed} SECURITY SCAN(S) FAILED")
        return 1

if __name__ == "__main__":
    sys.exit(main())
