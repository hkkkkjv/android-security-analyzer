import argparse
import json
import os
import sys
import time
import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analyzer import NetworkSecurityConfigAnalyzer

COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[93m",
    "MEDIUM":   "\033[33m",
    "LOW":      "\033[92m",
    "RESET":    "\033[0m",
    "BOLD":     "\033[1m",
}


def print_vulnerability(v):
    color = COLORS.get(v.severity, "")
    reset = COLORS["RESET"]
    print(f"\n{color}[{v.severity}]{reset} {v.description}")
    print(f"  ID:           {v.id}")
    print(f"  CVSS:         {v.cvss_score}")
    print(f"  Категория:    {v.category}")
    print(f"  Файл:         {v.location}")
    print(f"  Исправление:  {v.recommendation}")


def print_summary(vulnerabilities, duration_ms):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for v in vulnerabilities:
        counts[v.severity] = counts.get(v.severity, 0) + 1

    bold, reset = COLORS["BOLD"], COLORS["RESET"]
    print(f"\n{bold}{'=' * 60}{reset}")
    print(f"{bold}Итого: {len(vulnerabilities)} проблем(а)  |  Время анализа: {duration_ms} мс{reset}")
    print(f"  🔴 CRITICAL : {counts['CRITICAL']}")
    print(f"  🟠 HIGH     : {counts['HIGH']}")
    print(f"  🟡 MEDIUM   : {counts['MEDIUM']}")
    print(f"  🟢 LOW      : {counts['LOW']}")
    print(f"{bold}{'=' * 60}{reset}")


def save_report(vulnerabilities, project_path, output_path, duration_ms):
    report = {
        "scan_metadata": {
            "scan_date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "project_path": project_path,
            "scan_duration_ms": duration_ms,
        },
        "vulnerabilities": [
            {
                "id": v.id,
                "severity": v.severity,
                "cvss_score": v.cvss_score,
                "category": v.category,
                "description": v.description,
                "location": v.location,
                "recommendation": v.recommendation,
            }
            for v in vulnerabilities
        ],
        "summary": {
            "total_issues": len(vulnerabilities),
            "critical": sum(1 for v in vulnerabilities if v.severity == "CRITICAL"),
            "high":     sum(1 for v in vulnerabilities if v.severity == "HIGH"),
            "medium":   sum(1 for v in vulnerabilities if v.severity == "MEDIUM"),
            "low":      sum(1 for v in vulnerabilities if v.severity == "LOW"),
        },
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print(f"\nОтчёт сохранён: {os.path.abspath(output_path)}")


def main():
    parser = argparse.ArgumentParser(
        description="Android Security Analyzer — статический анализатор сетевой безопасности Android-приложений"
    )
    parser.add_argument("--project", required=True, help="Путь к директории Android-проекта")
    parser.add_argument("--output", default="report.json", help="Путь для сохранения JSON-отчёта (по умолчанию: report.json)")
    args = parser.parse_args()

    project_path = os.path.normpath(args.project)

    if not os.path.isdir(project_path):
        print(f"Ошибка: директория не найдена: {project_path}")
        sys.exit(1)

    print(f"Анализируем: {project_path}\n")

    start = time.time()
    analyzer = NetworkSecurityConfigAnalyzer()
    vulnerabilities = analyzer.analyze(project_path)
    duration_ms = round((time.time() - start) * 1000)

    if not vulnerabilities:
        print("Уязвимостей не найдено.")
    else:
        for v in vulnerabilities:
            print_vulnerability(v)

    print_summary(vulnerabilities, duration_ms)
    save_report(vulnerabilities, project_path, args.output, duration_ms)

    has_blocking = any(v.severity in ("CRITICAL", "HIGH") for v in vulnerabilities)
    sys.exit(1 if has_blocking else 0)


if __name__ == "__main__":
    main()
