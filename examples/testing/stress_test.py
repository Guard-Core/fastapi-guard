#!/usr/bin/env python3
"""
FastAPI Guard Comprehensive Stress Test
========================================

Tests all security features of FastAPI Guard under realistic load conditions.

Features Tested:
- Rate limiting (global and per-endpoint)
- IP whitelist/blacklist enforcement
- Country-based filtering
- Cloud provider IP blocking
- Penetration attempt detection (XSS, SQLi, Path Traversal, Command Injection)
- User agent filtering and bot detection
- Security headers validation
- Content type and size enforcement
- Behavioral analysis and monitoring
- Authentication mechanisms
- Custom validators and hooks
- Time-based access control
- Honeypot detection
- WebSocket security

Usage:
    # Standard test
    `make stress-test`

    # High-load test
    `make high-load-stress-test`

    # Custom test (your own parameters)
    `make stress-test --url http://localhost:8000 -d 60 -c 10 --test-type custom`

    OR, locally:

    # Standard test
    python stress_test.py --url http://localhost:8000 -d 60 -c 10

    # High-load test
    python stress_test.py --url http://localhost:8000 -d 120 -c 50 --test-type high_load

    # Custom test (your own parameters)
    python stress_test.py --url http://localhost:8000 -d 30 -c 5 --test-type custom
"""

import argparse
import asyncio
import json
import os
import random
import statistics
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import aiohttp

CHARTS_NEED_MATPLOTLIB = (
    "Charts skipped: they need matplotlib, which is installed only on "
    "Python 3.11 and newer because the only pillow without open advisories "
    "needs 3.11"
)


def ensure_results_dir(test_type: str = "standard") -> str:
    """Ensure results directory exists and return the path."""
    base_dir = Path("examples/testing/results")
    results_dir = base_dir / test_type

    base_dir.mkdir(exist_ok=True)
    results_dir.mkdir(exist_ok=True)

    return str(results_dir)


@dataclass
class RequestResult:
    """Result of a single HTTP request."""

    endpoint: str
    status: int
    duration: float
    success: bool
    category: str
    error: str | None = None
    blocked: bool = False
    security_triggered: bool = False


@dataclass
class SecurityStats:
    """Security-specific statistics."""

    category: str
    total_requests: int
    blocked_count: int
    passed_count: int
    error_count: int
    avg_response_time_ms: float
    block_rate: float
    status_codes: dict[int, int]


class FastAPIGuardStressTest:
    """
    Comprehensive stress test for FastAPI Guard security middleware.

    Tests all security features under realistic load conditions and
    provides detailed security-focused metrics.
    """

    def __init__(
        self,
        base_url: str,
        duration: int,
        concurrency: int,
        ramp_up: int = 0,
        delay: float = 0,
        verbose: bool = False,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.duration = duration
        self.concurrency = concurrency
        self.ramp_up = ramp_up
        self.delay = delay
        self.verbose = verbose
        self.results: list[RequestResult] = []
        self.running = True
        self.start_time = 0
        self.end_time = 0

        # Test scenario distribution
        self.test_scenarios = [
            # Basic functionality (30%)
            (self.test_root, 15),
            (self.test_health_check, 15),
            # Rate limiting (20%)
            (self.test_rate_limiting, 10),
            (self.test_strict_rate_limit, 5),
            (self.test_custom_rate_limit, 5),
            # Security attacks (25%)
            (self.test_xss_detection, 5),
            (self.test_sql_injection, 5),
            (self.test_path_traversal, 5),
            (self.test_command_injection, 5),
            (self.test_mixed_attack, 5),
            # Access control (10%)
            (self.test_ip_whitelist, 3),
            (self.test_ip_blacklist, 3),
            (self.test_cloud_blocking, 4),
            # Bot detection (5%)
            (self.test_bot_blocking, 3),
            (self.test_honeypot, 2),
            # Behavioral (5%)
            (self.test_usage_monitoring, 3),
            (self.test_frequency_detection, 2),
            # Headers & Content (5%)
            (self.test_security_headers, 3),
            (self.test_content_filtering, 2),
        ]

    async def make_request(
        self,
        session: aiohttp.ClientSession,
        method: str,
        url: str,
        category: str,
        expected_block: bool = False,
        **kwargs: Any,
    ) -> RequestResult:
        """
        Make a single request and return a RequestResult.

        Args:
            session: aiohttp client session
            method: HTTP method
            url: Full URL to request
            category: Test category for metrics
            expected_block: Whether this request should be blocked
            **kwargs: Additional request parameters
        """
        start_time = time.time()
        try:
            async with session.request(method, url, **kwargs) as response:
                duration = time.time() - start_time
                await response.text()

                # Determine if security was triggered
                status = response.status
                blocked = status in [403, 429]  # Forbidden or Rate Limited
                security_triggered = blocked or status in [400, 401]

                # Success means request completed and behaved as expected
                if expected_block:
                    success = blocked
                else:
                    success = 200 <= status < 400

                return RequestResult(
                    endpoint=url,
                    status=status,
                    duration=duration,
                    success=success,
                    category=category,
                    blocked=blocked,
                    security_triggered=security_triggered,
                )
        except Exception as e:
            duration = time.time() - start_time
            return RequestResult(
                endpoint=url,
                status=0,
                duration=duration,
                success=False,
                category=category,
                error=str(e),
            )

    # ==================== Basic Tests ====================

    async def test_root(self, session: aiohttp.ClientSession) -> RequestResult:
        """Test root endpoint (should always pass)."""
        url = f"{self.base_url}/"
        return await self.make_request(session, "GET", url, "basic")

    async def test_health_check(self, session: aiohttp.ClientSession) -> RequestResult:
        """Test health check (excluded from security checks)."""
        url = f"{self.base_url}/basic/health"
        return await self.make_request(session, "GET", url, "basic")

    # ==================== Rate Limiting Tests ====================

    async def test_rate_limiting(self, session: aiohttp.ClientSession) -> RequestResult:
        """Test global rate limiting."""
        # Simulate requests from different IPs
        ip_suffix = random.randint(1, 254)
        ip_address = f"172.18.{random.randint(1, 255)}.{ip_suffix}"
        headers = {"X-Forwarded-For": ip_address}
        url = f"{self.base_url}/"

        return await self.make_request(
            session, "GET", url, "rate_limiting", headers=headers
        )

    async def test_strict_rate_limit(
        self, session: aiohttp.ClientSession
    ) -> RequestResult:
        """Test strict rate limit endpoint (1 req/10s)."""
        url = f"{self.base_url}/rate/strict-limit"
        return await self.make_request(
            session, "GET", url, "rate_limiting", expected_block=True
        )

    async def test_custom_rate_limit(
        self, session: aiohttp.ClientSession
    ) -> RequestResult:
        """Test custom rate limit endpoint (5 req/60s)."""
        url = f"{self.base_url}/rate/custom-limit"
        return await self.make_request(session, "GET", url, "rate_limiting")

    # ==================== Security Attack Tests ====================

    async def test_xss_detection(self, session: aiohttp.ClientSession) -> RequestResult:
        """Test XSS attack detection."""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
        ]
        payload = random.choice(xss_payloads)
        url = f"{self.base_url}/test/xss-test"

        return await self.make_request(
            session,
            "POST",
            url,
            "penetration_detection",
            json={"payload": payload},
            expected_block=True,
        )

    async def test_sql_injection(self, session: aiohttp.ClientSession) -> RequestResult:
        """Test SQL injection detection."""
        sql_payloads = [
            "' OR '1'='1",
            "admin'--",
            "1' UNION SELECT NULL--",
            "'; DROP TABLE users--",
        ]
        payload = random.choice(sql_payloads)
        url = f"{self.base_url}/test/sql-injection?query={payload}"

        return await self.make_request(
            session, "POST", url, "penetration_detection", expected_block=True
        )

    async def test_path_traversal(
        self, session: aiohttp.ClientSession
    ) -> RequestResult:
        """Test path traversal attack detection."""
        paths = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
        ]
        path = random.choice(paths)
        url = f"{self.base_url}/test/path-traversal/{path}"

        return await self.make_request(
            session, "GET", url, "penetration_detection", expected_block=True
        )

    async def test_command_injection(
        self, session: aiohttp.ClientSession
    ) -> RequestResult:
        """Test command injection detection."""
        commands = [
            "; ls -la",
            "| cat /etc/passwd",
            "&& whoami",
            "`cat /etc/shadow`",
        ]
        command = random.choice(commands)
        url = f"{self.base_url}/test/command-injection"

        return await self.make_request(
            session,
            "POST",
            url,
            "penetration_detection",
            json={"command": command},
            expected_block=True,
        )

    async def test_mixed_attack(self, session: aiohttp.ClientSession) -> RequestResult:
        """Test multiple attack vectors simultaneously."""
        url = f"{self.base_url}/test/mixed-attack"
        payload = {
            "input": "<script>alert('xss')</script>",
            "query": "' OR '1'='1",
            "path": "../../../etc/passwd",
            "cmd": "; ls",
        }

        return await self.make_request(
            session,
            "POST",
            url,
            "penetration_detection",
            json=payload,
            expected_block=True,
        )

    # ==================== Access Control Tests ====================

    async def test_ip_whitelist(self, session: aiohttp.ClientSession) -> RequestResult:
        """Test IP whitelist enforcement."""
        # Use non-whitelisted IP
        headers = {"X-Forwarded-For": "203.0.113.1"}
        url = f"{self.base_url}/access/ip-whitelist"

        return await self.make_request(
            session, "GET", url, "access_control", headers=headers, expected_block=True
        )

    async def test_ip_blacklist(self, session: aiohttp.ClientSession) -> RequestResult:
        """Test IP blacklist enforcement."""
        # Use blacklisted IP range
        headers = {"X-Forwarded-For": "192.168.1.50"}
        url = f"{self.base_url}/access/ip-blacklist"

        return await self.make_request(
            session, "GET", url, "access_control", headers=headers, expected_block=True
        )

    async def test_cloud_blocking(
        self, session: aiohttp.ClientSession
    ) -> RequestResult:
        """Test cloud provider IP blocking."""
        url = f"{self.base_url}/access/no-cloud"
        return await self.make_request(session, "GET", url, "access_control")

    # ==================== Bot Detection Tests ====================

    async def test_bot_blocking(self, session: aiohttp.ClientSession) -> RequestResult:
        """Test bot user agent blocking."""
        bot_agents = [
            "badbot/1.0",
            "evil-crawler/2.0",
            "sqlmap/1.0",
            "python-requests/2.0 bot",
        ]
        headers = {"User-Agent": random.choice(bot_agents)}
        url = f"{self.base_url}/content/no-bots"

        return await self.make_request(
            session, "GET", url, "bot_detection", headers=headers, expected_block=True
        )

    async def test_honeypot(self, session: aiohttp.ClientSession) -> RequestResult:
        """Test honeypot field detection."""
        # Bots fill honeypot fields
        payload = {
            "input": "legitimate data",
            "honeypot_field": "bot filled this",  # This should trigger detection
        }
        url = f"{self.base_url}/advanced/honeypot"

        return await self.make_request(
            session, "POST", url, "bot_detection", json=payload, expected_block=True
        )

    # ==================== Behavioral Tests ====================

    async def test_usage_monitoring(
        self, session: aiohttp.ClientSession
    ) -> RequestResult:
        """Test endpoint usage monitoring."""
        url = f"{self.base_url}/behavior/usage-monitor"
        return await self.make_request(session, "GET", url, "behavioral")

    async def test_frequency_detection(
        self, session: aiohttp.ClientSession
    ) -> RequestResult:
        """Test suspicious request frequency detection."""
        url = f"{self.base_url}/behavior/suspicious-frequency"
        return await self.make_request(session, "GET", url, "behavioral")

    # ==================== Headers & Content Tests ====================

    async def test_security_headers(
        self, session: aiohttp.ClientSession
    ) -> RequestResult:
        """Test security headers presence."""
        url = f"{self.base_url}/headers/"
        return await self.make_request(session, "GET", url, "security_headers")

    async def test_content_filtering(
        self, session: aiohttp.ClientSession
    ) -> RequestResult:
        """Test content type filtering."""
        url = f"{self.base_url}/content/json-only"
        # Send wrong content type
        return await self.make_request(
            session,
            "POST",
            url,
            "content_filtering",
            data="not json",
            headers={"Content-Type": "text/plain"},
            expected_block=True,
        )

    # ==================== Worker and Execution ====================

    async def worker(self, worker_id: int) -> None:
        """Worker that makes requests continuously."""
        if self.ramp_up > 0:
            delay = (worker_id / self.concurrency) * self.ramp_up
            await asyncio.sleep(delay)

        # Create weighted test scenario list
        weighted_scenarios = []
        for scenario, weight in self.test_scenarios:
            weighted_scenarios.extend([scenario] * weight)

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30)
        ) as session:
            while self.running:
                test_method = random.choice(weighted_scenarios)

                result = await test_method(session)
                self.results.append(result)

                if self.verbose and len(self.results) % 100 == 0:
                    print(f"Progress: {len(self.results)} requests completed")

                if self.delay > 0:
                    await asyncio.sleep(self.delay)

    async def run(self) -> None:
        """Run the stress test."""
        print("=" * 80)
        print("FASTAPI GUARD COMPREHENSIVE STRESS TEST")
        print("=" * 80)
        print(f"\nTarget URL: {self.base_url}")
        print(f"Duration: {self.duration} seconds")
        print(f"Concurrency: {self.concurrency} workers")
        print(f"Ramp-up: {self.ramp_up} seconds")
        print(f"Request delay: {self.delay} seconds")
        print("\nStarting test...\n")

        self.start_time = int(time.time())
        self.running = True
        workers = [self.worker(i) for i in range(self.concurrency)]

        async def stop_after_duration() -> None:
            await asyncio.sleep(self.duration)
            self.running = False

        await asyncio.gather(stop_after_duration(), *workers)
        self.end_time = int(time.time())

        print(f"\n✓ Test completed: {len(self.results)} total requests")

    def analyze_results(self) -> dict[str, Any]:
        """Analyze results with security-focused metrics."""
        if not self.results:
            return {
                "summary": {
                    "total_requests": 0,
                    "requests_per_second": 0,
                    "overall_success_rate": 0,
                    "duration": 0,
                },
                "security": {},
                "categories": [],
            }

        actual_duration = self.end_time - self.start_time
        total_requests = len(self.results)
        successful_requests = sum(1 for r in self.results if r.success)
        requests_per_second = (
            total_requests / actual_duration if actual_duration > 0 else 0
        )
        success_rate = (
            (successful_requests / total_requests) * 100 if total_requests > 0 else 0
        )

        # Security-specific analysis
        blocked_requests = sum(1 for r in self.results if r.blocked)
        security_triggered = sum(1 for r in self.results if r.security_triggered)
        penetration_blocked = sum(
            1
            for r in self.results
            if r.category == "penetration_detection" and r.blocked
        )
        penetration_total = sum(
            1 for r in self.results if r.category == "penetration_detection"
        )

        # Category-based analysis
        category_results = defaultdict(list)
        for result in self.results:
            category_results[result.category].append(result)

        category_stats = []
        for category, results in sorted(category_results.items()):
            durations = [r.duration for r in results]
            blocked = sum(1 for r in results if r.blocked)
            passed = sum(1 for r in results if not r.blocked and r.status == 200)
            errors = sum(1 for r in results if r.error or r.status == 0)

            status_counts: dict[int, int] = defaultdict(int)
            for r in results:
                status_counts[r.status] += 1

            avg_time = statistics.mean(durations) if durations else 0.0
            block_rate = (blocked / len(results)) * 100 if results else 0.0

            category_stats.append(
                SecurityStats(
                    category=category,
                    total_requests=len(results),
                    blocked_count=blocked,
                    passed_count=passed,
                    error_count=errors,
                    avg_response_time_ms=avg_time * 1000,
                    block_rate=block_rate,
                    status_codes=dict(status_counts),
                )
            )

        return {
            "summary": {
                "total_requests": total_requests,
                "requests_per_second": requests_per_second,
                "overall_success_rate": success_rate,
                "duration": actual_duration,
            },
            "security": {
                "total_blocked": blocked_requests,
                "security_triggered": security_triggered,
                "penetration_attempts": penetration_total,
                "penetration_blocked": penetration_blocked,
                "penetration_block_rate": (
                    (penetration_blocked / penetration_total) * 100
                    if penetration_total > 0
                    else 0
                ),
                "block_rate": (blocked_requests / total_requests) * 100,
            },
            "categories": category_stats,
        }

    def generate_report(self, results: dict[str, Any]) -> None:
        """Generate comprehensive security report."""
        report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        print("\n" + "=" * 80)
        print(f"FASTAPI GUARD SECURITY TEST REPORT - {report_time}")
        print("=" * 80)

        summary = results["summary"]
        security = results["security"]

        print("\n📊 OVERALL PERFORMANCE:")
        print(f"  Total Requests:      {summary['total_requests']:,}")
        print(f"  Requests/Second:     {summary['requests_per_second']:.2f}")
        print(f"  Success Rate:        {summary['overall_success_rate']:.1f}%")
        print(f"  Duration:            {summary['duration']:.1f}s")

        print("\n🛡️  SECURITY METRICS:")
        print(f"  Total Blocked:           {security['total_blocked']:,}")
        print(f"  Security Triggered:      {security['security_triggered']:,}")
        print(f"  Block Rate:              {security['block_rate']:.1f}%")
        print(f"  Penetration Attempts:    {security['penetration_attempts']:,}")
        print(f"  Penetration Blocked:     {security['penetration_blocked']:,}")
        print(f"  Penetration Block Rate:  {security['penetration_block_rate']:.1f}%")

        print("\n📁 CATEGORY BREAKDOWN:")
        for stat in results["categories"]:
            print(f"\n  {stat.category.upper().replace('_', ' ')}:")
            print(f"    Requests:      {stat.total_requests:,}")
            print(f"    Blocked:       {stat.blocked_count:,} ({stat.block_rate:.1f}%)")
            print(f"    Passed:        {stat.passed_count:,}")
            print(f"    Errors:        {stat.error_count:,}")
            print(f"    Avg Time:      {stat.avg_response_time_ms:.2f}ms")
            print(f"    Status Codes:  {dict(sorted(stat.status_codes.items()))}")

        print("\n" + "=" * 80)

    def save_json_report(self, results: dict[str, Any], filename: str) -> None:
        """Save test results to JSON file."""
        report = {
            "timestamp": datetime.now().isoformat(),
            "configuration": {
                "base_url": self.base_url,
                "duration": self.duration,
                "concurrency": self.concurrency,
                "ramp_up": self.ramp_up,
                "delay": self.delay,
            },
            "results": {
                **results["summary"],
                "security": results["security"],
                "categories": [
                    {
                        "category": stat.category,
                        "total_requests": stat.total_requests,
                        "blocked_count": stat.blocked_count,
                        "passed_count": stat.passed_count,
                        "error_count": stat.error_count,
                        "avg_response_time_ms": stat.avg_response_time_ms,
                        "block_rate": stat.block_rate,
                        "status_codes": stat.status_codes,
                    }
                    for stat in results["categories"]
                ],
            },
        }

        with open(filename, "w") as f:
            json.dump(report, f, indent=2)

        print(f"\n💾 JSON report saved to {filename}")

    def generate_charts(self, results: dict[str, Any], filename_prefix: str) -> None:
        """Generate security-focused visualization charts."""
        if not results["categories"]:
            print("No data available for charts")
            return

        # Skip chart generation if 'ci' in filename (for CI environments)
        if "ci" in filename_prefix.lower():
            print("Skipping chart generation (CI mode detected)")
            return

        try:
            import matplotlib.pyplot as plt
        except ImportError:
            print(CHARTS_NEED_MATPLOTLIB)
            return

        categories = [s.category.replace("_", "\n") for s in results["categories"]]
        blocked = [s.blocked_count for s in results["categories"]]
        passed = [s.passed_count for s in results["categories"]]
        avg_times = [s.avg_response_time_ms for s in results["categories"]]
        block_rates = [s.block_rate for s in results["categories"]]

        # Security effectiveness chart
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 10))

        x = range(len(categories))
        width = 0.35

        ax1.bar(x, blocked, width, label="Blocked", color="red", alpha=0.7)
        ax1.bar(
            [i + width for i in x],
            passed,
            width,
            label="Passed",
            color="green",
            alpha=0.7,
        )
        ax1.set_xlabel("Security Category")
        ax1.set_ylabel("Request Count")
        ax1.set_title("FastAPI Guard Security Enforcement")
        ax1.set_xticks([i + width / 2 for i in x])
        ax1.set_xticklabels(categories, rotation=45, ha="right", fontsize=8)
        ax1.legend()
        ax1.grid(axis="y", alpha=0.3)

        # Block rate and response time
        ax2_twin = ax2.twinx()

        bars = ax2.bar(x, block_rates, color="orange", alpha=0.7)  # noqa: F841
        ax2.set_ylabel("Block Rate (%)", color="orange")
        ax2.set_xlabel("Security Category")
        ax2.tick_params(axis="y", labelcolor="orange")
        ax2.set_xticks(x)
        ax2.set_xticklabels(categories, rotation=45, ha="right", fontsize=8)

        line = ax2_twin.plot(  # noqa: F841
            x,
            avg_times,
            color="blue",
            marker="o",
            linewidth=2,
            label="Avg Response Time",
        )
        ax2_twin.set_ylabel("Response Time (ms)", color="blue")
        ax2_twin.tick_params(axis="y", labelcolor="blue")

        ax2.set_title("Security Block Rate & Response Time")
        ax2.grid(axis="y", alpha=0.3)

        plt.tight_layout()
        plt.savefig(f"{filename_prefix}_security_analysis.png", dpi=150)
        plt.close()

        print(f"📊 Charts saved with prefix {filename_prefix}")


async def main() -> int:
    """Parse arguments and run the stress test."""
    parser = argparse.ArgumentParser(
        description="FastAPI Guard Comprehensive Stress Test",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--url", default="http://localhost:8000", help="Base URL of the API"
    )
    parser.add_argument(
        "-d", "--duration", type=int, default=60, help="Test duration in seconds"
    )
    parser.add_argument(
        "-c", "--concurrency", type=int, default=10, help="Number of concurrent workers"
    )
    parser.add_argument(
        "-r", "--ramp-up", type=int, default=5, help="Ramp-up period in seconds"
    )
    parser.add_argument(
        "--delay", type=float, default=0.05, help="Delay between requests in seconds"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-o", "--output", help="Output prefix for reports and charts")
    parser.add_argument(
        "--test-type",
        default="standard",
        choices=["standard", "high_load", "custom"],
        help="Type of test (affects output directory)",
    )
    args = parser.parse_args()

    try:
        test = FastAPIGuardStressTest(
            base_url=args.url,
            duration=args.duration,
            concurrency=args.concurrency,
            ramp_up=args.ramp_up,
            delay=args.delay,
            verbose=args.verbose,
        )

        await test.run()

        results = test.analyze_results()
        test.generate_report(results)

        results_dir = ensure_results_dir(args.test_type)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if args.output:
            output_prefix = args.output
        else:
            output_prefix = f"fastapi_guard_{args.test_type}_{timestamp}"

        output_path = os.path.join(results_dir, output_prefix)

        test.save_json_report(results, f"{output_path}.json")
        test.generate_charts(results, output_path)

        print(f"\n✅ Results saved to: {results_dir}")

        # Return non-zero if security isn't working
        security = results["security"]
        if security["penetration_block_rate"] < 50:
            print(
                f"\n⚠️  WARNING: Low penetration block rate ({security['penetration_block_rate']:.1f}%)"  # noqa: E501
            )
            return 1

        return 0

    except KeyboardInterrupt:
        print("\n\n⚠️  Test interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Error running stress test: {e}")
        import traceback

        traceback.print_exc()
        return 2


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
