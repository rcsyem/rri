import argparse
import asyncio
import importlib.metadata
import json
import os
import sys

from core.scope import ScopeEngine
from core.http_engine import HTTPEngine
from core.correlation_engine import CorrelationEngine
from core.reporting import ReportGenerator

from modules.technology import TechnologyDetector
from modules.api_discovery import APIDiscovery
from modules.headers_analysis import HeadersAnalyzer
from modules.security_checks import SecurityChecks
from modules.crawler import Crawler
from modules.path_discovery import PathDiscovery
from modules.js_analysis import JSAnalyzer
from modules.dns_info import DNSInfo
from modules.http_info import HTTPInfo
from modules.tls_analysis import TLSAnalysis


def get_version():
    try:
        return importlib.metadata.version("rri-recon-intelligence")
    except importlib.metadata.PackageNotFoundError:
        return "0.1.0"


class Terminal:
    COLORS = {
        "reset": "\033[0m",
        "red": "\033[31m",
        "green": "\033[32m",
        "yellow": "\033[33m",
        "blue": "\033[34m",
        "cyan": "\033[36m",
        "bold": "\033[1m",
    }

    def __init__(self, enabled=True):
        self.enabled = enabled

    def color(self, text, color):
        if not self.enabled:
            return str(text)

        code = self.COLORS.get(color)
        if not code:
            return str(text)

        return f"{code}{text}{self.COLORS['reset']}"

    def info(self, message):
        print(self.color(f"[*] {message}", "cyan"))

    def success(self, message):
        print(self.color(f"[+] {message}", "green"))

    def warning(self, message):
        print(self.color(f"[!] {message}", "yellow"))

    def error(self, message):
        print(self.color(f"[-] {message}", "red"))


def build_summary(results):
    def count_items(module_name, list_name):
        module = results.get(module_name)

        if not isinstance(module, dict):
            return 0

        items = module.get(list_name, [])
        return len(items) if isinstance(items, list) else 0

    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for module_name, list_name in (
        ("headers_analysis", "findings"),
        ("security_checks", "findings"),
        ("correlation", "correlations"),
    ):
        module = results.get(module_name)

        if not isinstance(module, dict):
            continue

        items = module.get(list_name, [])

        if not isinstance(items, list):
            continue

        for item in items:
            if not isinstance(item, dict):
                continue

            severity = str(item.get("severity", "info")).lower()

            if severity in severity_counts:
                severity_counts[severity] += 1

    return {
        "technologies": count_items("technology", "technologies"),
        "api_endpoints": count_items("api_discovery", "endpoints"),
        "discovered_urls": count_items("crawler", "discovered_urls"),
        "discovered_paths": count_items("path_discovery", "discovered_paths"),
        "dns_records": count_items("dns_info", "records"),
        "js_scripts_analyzed": count_items("js_analysis", "analyzed_scripts"),
        "header_findings": count_items("headers_analysis", "findings"),
        "security_findings": count_items("security_checks", "findings"),
        "correlations": count_items("correlation", "correlations"),
        "severity": severity_counts,
    }


def print_summary(results, terminal):
    summary = build_summary(results)

    print()
    print(terminal.color("=" * 48, "blue"))
    print(terminal.color("             RRI SCAN SUMMARY", "bold"))
    print(terminal.color("=" * 48, "blue"))

    print(f"Technologies detected : {summary['technologies']}")
    print(f"API endpoints         : {summary['api_endpoints']}")
    print(f"Discovered URLs       : {summary['discovered_urls']}")
    print(f"Discovered paths      : {summary['discovered_paths']}")
    print(f"DNS records           : {summary['dns_records']}")
    print(f"JS scripts analyzed   : {summary['js_scripts_analyzed']}")
    print(f"Header findings       : {summary['header_findings']}")
    print(f"Security findings     : {summary['security_findings']}")
    print(f"Correlations          : {summary['correlations']}")

    print()
    print(terminal.color("Severity Overview", "bold"))

    severity_colors = {
        "critical": "red",
        "high": "red",
        "medium": "yellow",
        "low": "cyan",
        "info": "blue",
    }

    for severity, count in summary["severity"].items():
        label = severity.upper().ljust(9)
        print(
            f"{terminal.color(label, severity_colors[severity])}: {count}"
        )

    print(terminal.color("=" * 48, "blue"))
    print()


async def run_scan(target, scope):
    engine = HTTPEngine(scope=scope)

    print("\n===== FETCHING TARGET =====")
    response = await engine.fetch(target)

    if response.get("status") != "completed":
        return {
            "status": response.get("status", "error"),
            "target": target,
            "technology": None,
            "api_discovery": None,
            "headers_analysis": None,
            "security_checks": None,
            "crawler": None,
            "path_discovery": None,
            "js_analysis": None,
            "dns_info": None,
            "http_info": None,
            "tls_analysis": None,
            "correlation": None,
            "error": response.get("error"),
        }

    print("[+] Initial page fetched successfully")

    technology_detector = TechnologyDetector(engine=engine)
    api_detector = APIDiscovery(engine=engine, max_script_files=10)
    headers_analyzer = HeadersAnalyzer(engine=engine)
    security_analyzer = SecurityChecks(engine=engine)
    crawler = Crawler(engine=engine)
    path_discovery = PathDiscovery(engine=engine, max_script_files=10)
    js_analyzer = JSAnalyzer(engine=engine, max_script_files=10)
    dns_info = DNSInfo(engine=engine)
    http_info = HTTPInfo(engine=engine)
    tls_analysis = TLSAnalysis(engine=engine)

    technology_results = await technology_detector.scan(
        target, response=response
    )

    api_results = await api_detector.scan(
        target, response=response
    )

    headers_results = await headers_analyzer.scan(
        target, response=response
    )

    security_results = await security_analyzer.scan(
        target, response=response
    )

    print("[+] Starting website crawl")
    crawl_results = await crawler.crawl(target)

    print("[+] Starting path discovery")
    path_results = await path_discovery.scan(
        target, response=response, crawl_results=crawl_results
    )

    print("[+] Starting JavaScript analysis")
    js_results = await js_analyzer.scan(
        target, response=response
    )

    print("[+] Gathering DNS information")
    dns_results = await dns_info.scan(target)

    print("[+] Extracting HTTP information")
    http_info_results = await http_info.scan(
        target, response=response
    )

    print("[+] Analyzing TLS certificate")
    tls_results = await tls_analysis.scan(target)

    print("[+] Analysis modules completed")
    print("[+] Running Correlation Engine")

    correlation_engine = CorrelationEngine()

    correlation_results = correlation_engine.analyze(
        target=response.get("url", target),
        technology=technology_results,
        api_discovery=api_results,
        headers_analysis=headers_results,
        security_checks=security_results,
    )

    return {
        "status": "completed",
        "target": response.get("url", target),
        "technology": technology_results,
        "api_discovery": api_results,
        "headers_analysis": headers_results,
        "security_checks": security_results,
        "crawler": crawl_results,
        "path_discovery": path_results,
        "js_analysis": js_results,
        "dns_info": dns_results,
        "http_info": http_info_results,
        "tls_analysis": tls_results,
        "correlation": correlation_results,
        "error": None,
    }


def main():
    parser = argparse.ArgumentParser(
        prog="rri",
        description="RRI - Recon Intelligence",
    )

    parser.add_argument(
        "-u",
        "--url",
        required=True,
        help="Authorized target URL",
    )

    parser.add_argument(
        "-f",
        "--format",
        choices=("html", "json", "both"),
        default="html",
        help="Report format: html, json, or both (default: html)",
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Output report path",
    )

    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"RRI {get_version()}",
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable terminal colors",
    )

    args = parser.parse_args()

    color_enabled = (
        sys.stdout.isatty()
        and not args.no_color
        and "NO_COLOR" not in os.environ
    )

    terminal = Terminal(enabled=color_enabled)

    try:
        scope = ScopeEngine(args.url)
        allowed, reason = scope.check(args.url)

        print("\n===== RRI SCOPE ENGINE =====")
        print(f"Target: {args.url}")

        if allowed:
            terminal.success("Scope status: AUTHORIZED")
        else:
            terminal.error("Scope status: BLOCKED")

        print(f"Reason: {reason}")

        if not allowed:
            raise SystemExit(1)

        print("\n===== RRI RECON SCAN =====")

        results = asyncio.run(run_scan(args.url, scope))

        if results["status"] != "completed":
            terminal.error(
                f"Scan failed: {results.get('error')}"
            )
            raise SystemExit(1)

        print_summary(results, terminal)

        generator = ReportGenerator()

        paths = generator.generate(
            results=results,
            target=results.get("target", args.url),
            report_format=args.format,
            output=args.output,
        )

        print("===== REPORTS GENERATED =====")

        for path in paths:
            terminal.success(str(path.resolve()))

        terminal.success("Scan completed successfully")

    except (
        ValueError,
        FileNotFoundError,
        RuntimeError,
        OSError,
    ) as error:
        terminal.error(str(error))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
