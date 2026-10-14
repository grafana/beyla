#!/usr/bin/env python3
"""Use an LLM agent to audit vendored packages for risky behavior.

The deterministic code in this file is only a context gatherer: it indexes the
vendor tree, extracts suspicious evidence snippets, and builds compact dossiers.
The actual judgment is delegated to an LLM backend, with Codex and Claude Code
supported.


For most verbose output and no pre-scan for potential analysis, run like this:

python3 scripts/vendor-audit-agent.py --llm-backend claude --review-scope all --package "github.com/AlessandroPomponio/go-gibberish" --min-severity low

The default review-scope will first do a cheap pass to not scan with LLM what doesn't look like potential problem.
--min-severity low says that we should report everything.
"""

from __future__ import annotations

import argparse
import dataclasses
import ipaddress
import json
import re
import subprocess
import sys
import tempfile
from collections import Counter
from collections import defaultdict
from pathlib import Path
from typing import Iterable


SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {name: idx for idx, name in enumerate(SEVERITIES, start=1)}
LLM_VERDICTS = ("clean", "benign_capability", "needs_review", "suspicious", "error")
LOWER_SEVERITY = {
    "critical": "high",
    "high": "medium",
    "medium": "low",
    "low": "low",
}

SOURCE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".go",
    ".h",
    ".hh",
    ".hpp",
    ".java",
    ".js",
    ".kt",
    ".m",
    ".mm",
    ".pl",
    ".py",
    ".rb",
    ".rs",
    ".s",
    ".scala",
    ".sh",
    ".ts",
    ".zig",
}

SPECIAL_SOURCE_FILES = {
    "BUILD",
    "BUILD.bazel",
    "Dockerfile",
    "Makefile",
}

NON_RUNTIME_DIRS = {
    ".github",
    "docs",
    "doc",
    "example",
    "examples",
    "fixtures",
    "mock",
    "mocks",
    "test",
    "testdata",
    "tests",
    "testutils",
    "testing",
}

GENERATED_MARKERS = (
    "code generated",
    "do not edit",
    "do not modify",
    "automatically generated",
)

EXTERNAL_URL_RE = re.compile(
    r"\bhttps?://(?P<host>[A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])"
    r"(?::\d+)?(?P<path>[^\s\"'`<>)\]}]*)"
)

NETWORK_API_RE = re.compile(
    r"\b(?:"
    r"http\.(?:Get|Post|PostForm|Head|NewRequest|NewRequestWithContext|DefaultClient)"
    r"|(?:net|tls)\.Dial(?:Context|Timeout)?"
    r"|grpc\.Dial(?:Context)?"
    r"|websocket\.(?:DefaultDialer|Dialer)"
    r"|dns\.Exchange"
    r"|net\.Lookup(?:Host|IP|CNAME|MX|NS|TXT|SRV|Addr)"
    r")\b"
)

LISTEN_API_RE = re.compile(
    r"\b(?:"
    r"net\.Listen"
    r"|http\.ListenAndServe(?:TLS)?"
    r"|grpc\.NewServer"
    r")\b"
)

FILE_READ_API_RE = re.compile(
    r"\b(?:"
    r"os\.(?:Open|OpenFile|ReadFile)"
    r"|ioutil\.ReadFile"
    r"|filepath\.Walk(?:Dir)?"
    r"|fs\.WalkDir"
    r")\b"
)

FILE_WRITE_API_RE = re.compile(
    r"\b(?:"
    r"os\.(?:Create|CreateTemp|Mkdir|MkdirAll|OpenFile|Remove|RemoveAll|Rename|Truncate|WriteFile)"
    r"|ioutil\.WriteFile"
    r")\b"
)

WRITE_FLAG_RE = re.compile(r"\bO_(?:APPEND|CREATE|RDWR|TRUNC|WRONLY)\b")

KERNEL_INTERNAL_PATH_RE = re.compile(
    r"(?i)(?:"
    r"/proc/(?:kallsyms|config\.gz|self/fdinfo/[^\s\"'`]+|self/fd/[^\s\"'`]+)"
    r"|/sys/kernel/(?:btf|tracing|debug/tracing)[^\s\"'`]*"
    r"|/sys/fs/bpf[^\s\"'`]*"
    r"|<tracefs>/[^\s\"'`]*"
    r"|tracefs"
    r"|bpffs"
    r")"
)

KERNEL_CAPABILITY_API_RE = re.compile(
    r"\b(?:"
    r"(?:sys\.)?BPF\("
    r"|unix\.SYS_BPF"
    r"|unix\.PerfEventOpen\("
    r"|unix\.Mmap(?:Ptr)?\("
    r"|unix\.Munmap\("
    r"|unix\.Syscall\("
    r"|syscall\.Syscall(?:N)?\("
    r"|unix\.Setrlimit\("
    r"|rlimit\.RemoveMemlock\("
    r")"
)

SENSITIVE_PATH_RE = re.compile(
    r"(?i)(?:"
    r"/etc/(?:shadow|sudoers|passwd|ssh/ssh_host_[^\s\"'`]+)"
    r"|/(?:root|home)/[^\s\"'`]*/\.ssh/[^\s\"'`]+"
    r"|\.ssh/(?:id_rsa|id_ed25519|id_dsa|known_hosts|config)"
    r"|\.aws/(?:credentials|config)"
    r"|\.docker/config\.json"
    r"|\.kube/config"
    r"|\.netrc"
    r"|/proc/(?:self/)?(?:environ|cmdline|mem|root)"
    r"|/proc/[0-9]+/(?:environ|cmdline|mem|root)"
    r"|/var/run/secrets/kubernetes\.io/serviceaccount/(?:token|ca\.crt|namespace)"
    r")"
)

ABSOLUTE_SYSTEM_PATH_RE = re.compile(
    r"(?i)[\"`](/(?:etc|proc|root|run|sys|var/run|var/lib|home)/[^\"`]+)[\"`]"
)

SENSITIVE_ENV_RE = re.compile(
    r"\b(?:"
    r"AWS_ACCESS_KEY_ID"
    r"|AWS_SECRET_ACCESS_KEY"
    r"|AWS_SESSION_TOKEN"
    r"|AZURE_CLIENT_SECRET"
    r"|DOCKER_CONFIG"
    r"|GITHUB_TOKEN"
    r"|GITLAB_TOKEN"
    r"|GOOGLE_APPLICATION_CREDENTIALS"
    r"|KUBECONFIG"
    r"|NPM_TOKEN"
    r"|SSH_AUTH_SOCK"
    r"|VAULT_TOKEN"
    r"|SLACK_(?:TOKEN|WEBHOOK_URL)"
    r")\b"
)

PROCESS_EXEC_RE = re.compile(
    r"\b(?:"
    r"exec\.Command(?:Context)?"
    r"|os\.StartProcess"
    r"|syscall\.Exec"
    r"|forkExec"
    r"|Runtime\.getRuntime\(\)\.exec"
    r"|subprocess\.(?:Popen|run|call|check_call|check_output)"
    r"|ProcessBuilder"
    r")\b"
)

SHELL_NETWORK_RE = re.compile(
    r"(?i)\b(?:curl|wget|nc|netcat|ncat|socat|scp|sftp|ssh|rsync)\b"
)

DYNAMIC_CODE_RE = re.compile(
    r"\b(?:"
    r"plugin\.Open"
    r"|dlopen"
    r"|LoadLibrary"
    r"|System\.loadLibrary"
    r")\b"
)

CGO_RE = re.compile(r'^\s*import\s+"C"\s*$')
LINKNAME_RE = re.compile(r"^\s*//go:linkname\b")

METADATA_HOSTS = {
    "169.254.169.254",
    "169.254.170.2",
    "metadata.google.internal",
}

DOC_HOST_SUFFIXES = (
    ".example.com",
    ".example.org",
    ".example.net",
    ".ietf.org",
    ".w3.org",
)

DOC_HOSTS = {
    "example.com",
    "example.org",
    "example.net",
    "localhost",
}


@dataclasses.dataclass(frozen=True)
class ModuleInfo:
    path: str
    version: str


@dataclasses.dataclass(frozen=True)
class PackageInfo:
    import_path: str
    module_path: str
    module_version: str


@dataclasses.dataclass(frozen=True)
class SourceFile:
    path: Path
    package: PackageInfo
    generated: bool


@dataclasses.dataclass(frozen=True)
class Finding:
    severity: str
    rule: str
    category: str
    module: str
    module_version: str
    package: str
    path: str
    line: int
    evidence: str
    message: str

    def as_dict(self) -> dict[str, object]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class Dossier:
    package: PackageInfo
    source_files: tuple[SourceFile, ...]
    signals: tuple[Finding, ...]
    prompt: str

    @property
    def import_path(self) -> str:
        return self.package.import_path


@dataclasses.dataclass(frozen=True)
class LLMFinding:
    severity: str
    category: str
    path: str
    line: int
    evidence: str
    reasoning: str
    remediation: str
    likely_benign: bool

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "LLMFinding":
        return cls(
            severity=valid_severity(str(data.get("severity", "medium"))),
            category=str(data.get("category", "unknown")),
            path=str(data.get("path", "")),
            line=safe_int(data.get("line"), 0),
            evidence=str(data.get("evidence", "")),
            reasoning=str(data.get("reasoning", "")),
            remediation=str(data.get("remediation", "")),
            likely_benign=bool(data.get("likely_benign", False)),
        )

    def as_dict(self) -> dict[str, object]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class LLMAssessment:
    package: str
    module: str
    module_version: str
    verdict: str
    severity: str
    confidence: str
    summary: str
    findings: tuple[LLMFinding, ...]
    limitations: str
    raw_response: str = ""
    error: str = ""

    @classmethod
    def from_dict(
        cls,
        data: dict[str, object],
        package: PackageInfo,
        raw_response: str,
    ) -> "LLMAssessment":
        raw_findings = data.get("findings", [])
        findings: list[LLMFinding] = []
        if isinstance(raw_findings, list):
            findings = [
                LLMFinding.from_dict(item)
                for item in raw_findings
                if isinstance(item, dict)
            ]

        verdict = str(data.get("verdict", "needs_review"))
        if verdict not in LLM_VERDICTS:
            verdict = "needs_review"

        return cls(
            package=str(data.get("package") or package.import_path),
            module=str(data.get("module") or package.module_path),
            module_version=str(data.get("module_version") or package.module_version),
            verdict=verdict,
            severity=valid_severity(str(data.get("severity", "medium"))),
            confidence=str(data.get("confidence", "medium")),
            summary=str(data.get("summary", "")),
            findings=tuple(findings),
            limitations=str(data.get("limitations", "")),
            raw_response=raw_response,
        )

    @classmethod
    def error_result(cls, package: PackageInfo, error: str, raw_response: str = "") -> "LLMAssessment":
        return cls(
            package=package.import_path,
            module=package.module_path,
            module_version=package.module_version,
            verdict="error",
            severity="medium",
            confidence="low",
            summary="LLM analysis failed for this package.",
            findings=(),
            limitations="No package judgment was produced.",
            raw_response=raw_response,
            error=error,
        )

    def as_dict(self) -> dict[str, object]:
        data = dataclasses.asdict(self)
        data["findings"] = [finding.as_dict() for finding in self.findings]
        return data


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Use an LLM agent to audit vendored packages for suspicious behavior.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--vendor-dir",
        type=Path,
        default=Path("vendor"),
        help="Vendored dependency directory to scan.",
    )
    parser.add_argument(
        "--package",
        action="append",
        default=[],
        help="Limit scan to a module/package import-path prefix. May be repeated.",
    )
    parser.add_argument(
        "--include-tests",
        action="store_true",
        help="Include *_test.go files.",
    )
    parser.add_argument(
        "--include-non-runtime",
        action="store_true",
        help="Include docs, examples, tests, and testdata directories.",
    )
    parser.add_argument(
        "--skip-generated",
        action="store_true",
        help="Skip files marked as generated.",
    )
    parser.add_argument(
        "--review-scope",
        choices=("signals", "all"),
        default="signals",
        help="Review only packages with suspicious signals, or every package with runtime source.",
    )
    parser.add_argument(
        "--llm-backend",
        choices=("codex", "claude", "none"),
        default="codex",
        help="LLM backend. Use 'none' to print the gathered evidence without LLM judgment.",
    )
    parser.add_argument(
        "--codex-bin",
        default="codex",
        help="Codex CLI executable used when --llm-backend=codex.",
    )
    parser.add_argument(
        "--claude-bin",
        default="claude",
        help="Claude Code executable used when --llm-backend=claude.",
    )
    parser.add_argument(
        "--claude-tools",
        default="Read,Grep,Glob",
        help="Claude Code tools to expose. Empty string disables all tools.",
    )
    parser.add_argument(
        "--model",
        default="",
        help="Model to pass to the selected LLM. Empty uses the backend default.",
    )
    parser.add_argument(
        "--profile",
        default="",
        help="Codex config profile to use.",
    )
    parser.add_argument(
        "--llm-timeout",
        type=int,
        default=300,
        help="Seconds to wait for each LLM package assessment.",
    )
    parser.add_argument(
        "--llm-max-dossiers",
        type=int,
        default=25,
        help="Maximum package dossiers to send to the LLM. Use 0 for no limit.",
    )
    parser.add_argument(
        "--evidence-per-package",
        type=int,
        default=20,
        help="Maximum gathered evidence snippets per package dossier.",
    )
    parser.add_argument(
        "--dossier-chars",
        type=int,
        default=30000,
        help="Approximate maximum characters per package dossier prompt.",
    )
    parser.add_argument(
        "--save-prompts",
        type=Path,
        default=None,
        help="Optional directory where generated LLM prompts are written for inspection.",
    )
    parser.add_argument(
        "--min-severity",
        choices=SEVERITIES,
        default="medium",
        help="Minimum LLM severity to display in the text report.",
    )
    parser.add_argument(
        "--max-findings",
        type=int,
        default=50,
        help="Maximum displayed findings in the text report. Use 0 for all.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Write a machine-readable JSON report.",
    )
    parser.add_argument(
        "--fail-on",
        choices=("none",) + SEVERITIES,
        default="none",
        help="Exit with status 2 if any LLM assessment or finding at or above this severity exists.",
    )
    return parser.parse_args()


def valid_severity(value: str) -> str:
    value = value.lower()
    if value in SEVERITY_RANK:
        return value
    return "medium"


def safe_int(value: object, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def parse_modules(vendor_dir: Path) -> tuple[list[ModuleInfo], list[PackageInfo]]:
    modules_txt = vendor_dir / "modules.txt"
    if not modules_txt.exists():
        raise FileNotFoundError(f"{modules_txt} does not exist")

    modules: list[ModuleInfo] = []
    packages: list[PackageInfo] = []
    current: ModuleInfo | None = None

    for raw_line in modules_txt.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("# "):
            current = parse_module_header(line)
            modules.append(current)
            continue
        if line.startswith("##"):
            continue
        if current is None:
            continue
        packages.append(
            PackageInfo(
                import_path=line,
                module_path=current.path,
                module_version=current.version,
            )
        )

    return modules, packages


def parse_module_header(line: str) -> ModuleInfo:
    # Examples:
    #   # github.com/foo/bar v1.2.3
    #   # github.com/foo/bar v1.2.3 => ../bar
    #   # github.com/foo/bar => ../bar
    fields = line[2:].split()
    path = fields[0]
    version = ""
    if len(fields) > 1 and fields[1] != "=>":
        version = fields[1]
    return ModuleInfo(path=path, version=version)


def detect_generated(path: Path) -> bool:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            first_chunk = handle.read(4096).lower()
    except OSError:
        return False
    return any(marker in first_chunk for marker in GENERATED_MARKERS)


def collect_source_files(
    vendor_dir: Path,
    modules: list[ModuleInfo],
    packages: list[PackageInfo],
    package_filters: Iterable[str],
    include_tests: bool,
    include_non_runtime: bool,
    skip_generated: bool,
) -> list[SourceFile]:
    module_by_dir = {
        tuple(module.path.split("/")): module
        for module in modules
        if (vendor_dir / module.path).exists()
    }
    package_by_dir = {
        tuple(pkg.import_path.split("/")): pkg
        for pkg in packages
        if (vendor_dir / pkg.import_path).exists()
    }
    package_filters = tuple(package_filters)

    source_files: list[SourceFile] = []
    for path in vendor_dir.rglob("*"):
        if not path.is_file():
            continue
        if not is_source_file(path):
            continue
        if not include_tests and path.name.endswith("_test.go"):
            continue

        rel_parts = path.relative_to(vendor_dir).parts
        if not include_non_runtime and any(part in NON_RUNTIME_DIRS for part in rel_parts):
            continue

        package = package_for_path(rel_parts[:-1], package_by_dir, module_by_dir)
        if package is None:
            continue
        if package_filters and not matches_filter(package, package_filters):
            continue

        generated = detect_generated(path)
        if skip_generated and generated:
            continue

        source_files.append(SourceFile(path=path, package=package, generated=generated))

    return source_files


def is_source_file(path: Path) -> bool:
    if path.name in SPECIAL_SOURCE_FILES:
        return True
    return path.suffix.lower() in SOURCE_EXTENSIONS


def package_for_path(
    package_dir_parts: tuple[str, ...],
    package_by_dir: dict[tuple[str, ...], PackageInfo],
    module_by_dir: dict[tuple[str, ...], ModuleInfo],
) -> PackageInfo | None:
    for idx in range(len(package_dir_parts), 0, -1):
        prefix = package_dir_parts[:idx]
        package = package_by_dir.get(prefix)
        if package is not None:
            return package

    for idx in range(len(package_dir_parts), 0, -1):
        prefix = package_dir_parts[:idx]
        module = module_by_dir.get(prefix)
        if module is not None:
            import_path = "/".join(package_dir_parts)
            return PackageInfo(
                import_path=import_path,
                module_path=module.path,
                module_version=module.version,
            )

    return None


def matches_filter(package: PackageInfo, filters: tuple[str, ...]) -> bool:
    return any(
        package.import_path == prefix
        or package.import_path.startswith(prefix + "/")
        or package.module_path == prefix
        or package.module_path.startswith(prefix + "/")
        for prefix in filters
    )


def scan_file(source: SourceFile, repo_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        lines = source.path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return [
            make_finding(
                source,
                repo_root,
                line_no=0,
                rule="scan-error",
                category="scanner",
                severity="medium",
                evidence=str(exc),
                message="could not read source file",
            )
        ]

    for line_no, line in enumerate(lines, start=1):
        if "\x00" in line:
            continue
        findings.extend(scan_line(source, repo_root, line_no, line))

    return findings


def scan_line(source: SourceFile, repo_root: Path, line_no: int, line: str) -> list[Finding]:
    findings: list[Finding] = []
    comment = is_comment_line(line, source.path.suffix)

    for match in SENSITIVE_PATH_RE.finditer(line):
        findings.append(
            make_finding(
                source,
                repo_root,
                line_no,
                "sensitive-path",
                "filesystem",
                adjusted("high", comment),
                line,
                f"references sensitive path `{match.group(0)}`",
            )
        )

    if not comment and FILE_READ_API_RE.search(line) and ABSOLUTE_SYSTEM_PATH_RE.search(line):
        findings.append(
            make_finding(
                source,
                repo_root,
                line_no,
                "system-path-read",
                "filesystem",
                "medium",
                line,
                "reads from an absolute system path",
            )
        )

    if not comment and FILE_WRITE_API_RE.search(line):
        severity = "medium"
        message = "writes, removes, renames, or creates filesystem content"
        if ABSOLUTE_SYSTEM_PATH_RE.search(line) or WRITE_FLAG_RE.search(line):
            severity = "high"
            message = "writes or opens filesystem content with write-like flags"
        findings.append(
            make_finding(
                source,
                repo_root,
                line_no,
                "file-write",
                "filesystem",
                severity,
                line,
                message,
            )
        )

    for match in KERNEL_INTERNAL_PATH_RE.finditer(line):
        findings.append(
            make_finding(
                source,
                repo_root,
                line_no,
                "kernel-internal-path",
                "kernel",
                adjusted("medium", comment),
                line,
                f"references privileged kernel interface `{match.group(0)}`",
            )
        )

    if not comment and KERNEL_CAPABILITY_API_RE.search(line):
        findings.append(
            make_finding(
                source,
                repo_root,
                line_no,
                "kernel-capability-api",
                "kernel",
                "medium",
                line,
                "uses an API associated with kernel, eBPF, perf-event, mmap, or rlimit capabilities",
            )
        )

    for match in SENSITIVE_ENV_RE.finditer(line):
        findings.append(
            make_finding(
                source,
                repo_root,
                line_no,
                "sensitive-env",
                "secrets",
                adjusted("medium", comment),
                line,
                f"references sensitive environment variable `{match.group(0)}`",
            )
        )

    for match in EXTERNAL_URL_RE.finditer(line):
        host = normalize_host(match.group("host"))
        severity, rule, message = classify_url(host)
        findings.append(
            make_finding(
                source,
                repo_root,
                line_no,
                rule,
                "network",
                adjusted(severity, comment),
                line,
                message,
            )
        )

    if not comment and NETWORK_API_RE.search(line):
        findings.append(
            make_finding(
                source,
                repo_root,
                line_no,
                "network-call",
                "network",
                "medium",
                line,
                "uses an API that can initiate outbound network calls",
            )
        )

    if not comment and LISTEN_API_RE.search(line):
        findings.append(
            make_finding(
                source,
                repo_root,
                line_no,
                "network-listener",
                "network",
                "low",
                line,
                "opens or configures a network listener",
            )
        )

    if not comment and PROCESS_EXEC_RE.search(line):
        findings.append(
            make_finding(
                source,
                repo_root,
                line_no,
                "process-exec",
                "process",
                "high",
                line,
                "spawns a process or executes a command",
            )
        )

    if not comment and SHELL_NETWORK_RE.search(line) and looks_like_shell(source.path):
        findings.append(
            make_finding(
                source,
                repo_root,
                line_no,
                "shell-network-tool",
                "process",
                "high",
                line,
                "uses a shell/network transfer tool",
            )
        )

    if not comment and DYNAMIC_CODE_RE.search(line):
        findings.append(
            make_finding(
                source,
                repo_root,
                line_no,
                "dynamic-code-loading",
                "process",
                "medium",
                line,
                "loads dynamic code or native libraries",
            )
        )

    if not comment and CGO_RE.search(line):
        findings.append(
            make_finding(
                source,
                repo_root,
                line_no,
                "cgo",
                "native",
                "medium",
                line,
                "uses cgo to compile or call native code",
            )
        )

    if LINKNAME_RE.search(line):
        findings.append(
            make_finding(
                source,
                repo_root,
                line_no,
                "go-linkname",
                "native",
                "low",
                line,
                "uses //go:linkname to access non-exported Go symbols",
            )
        )

    return dedupe_findings(findings)


def make_finding(
    source: SourceFile,
    repo_root: Path,
    line_no: int,
    rule: str,
    category: str,
    severity: str,
    evidence: str,
    message: str,
) -> Finding:
    return Finding(
        severity=severity,
        rule=rule,
        category=category,
        module=source.package.module_path,
        module_version=source.package.module_version,
        package=source.package.import_path,
        path=relative_path(source.path, repo_root),
        line=line_no,
        evidence=trim_evidence(evidence),
        message=message,
    )


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.rule, finding.path, finding.line, finding.evidence)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def is_comment_line(line: str, suffix: str) -> bool:
    stripped = line.lstrip()
    if not stripped:
        return False
    if suffix in {".go", ".c", ".cc", ".cpp", ".h", ".hh", ".hpp", ".java", ".js", ".ts", ".kt", ".rs"}:
        return stripped.startswith(("//", "/*", "*"))
    if suffix in {".sh", ".py", ".pl", ".rb"}:
        return stripped.startswith("#")
    return False


def adjusted(severity: str, comment: bool) -> str:
    if comment:
        return LOWER_SEVERITY[severity]
    return severity


def normalize_host(host: str) -> str:
    host = host.strip("[]").lower()
    return host[:-1] if host.endswith(".") else host


def classify_url(host: str) -> tuple[str, str, str]:
    if host in METADATA_HOSTS:
        return (
            "high",
            "metadata-service-url",
            "references a cloud/container metadata service URL",
        )

    if is_private_host(host):
        return (
            "low",
            "local-url",
            "references a loopback, private, or link-local URL",
        )

    if host in DOC_HOSTS or host.endswith(DOC_HOST_SUFFIXES):
        return (
            "low",
            "doc-url",
            "references a documentation/example URL",
        )

    return (
        "low",
        "external-url",
        "references an external URL literal",
    )


def is_private_host(host: str) -> bool:
    if host in {"localhost", "ip6-localhost"}:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def looks_like_shell(path: Path) -> bool:
    return path.suffix.lower() in {".sh", ".bash", ".zsh"} or path.name in {"Makefile"}


def trim_evidence(line: str) -> str:
    return " ".join(line.strip().split())[:240]


def relative_path(path: Path, repo_root: Path) -> str:
    try:
        return path.relative_to(repo_root).as_posix()
    except ValueError:
        return path.as_posix()


def build_dossiers(
    sources: list[SourceFile],
    signals: list[Finding],
    repo_root: Path,
    review_scope: str,
    max_dossiers: int,
    evidence_per_package: int,
    dossier_chars: int,
) -> list[Dossier]:
    sources_by_package: dict[str, list[SourceFile]] = defaultdict(list)
    package_by_name: dict[str, PackageInfo] = {}
    for source in sources:
        sources_by_package[source.package.import_path].append(source)
        package_by_name[source.package.import_path] = source.package

    signals_by_package: dict[str, list[Finding]] = defaultdict(list)
    for signal in signals:
        signals_by_package[signal.package].append(signal)

    if review_scope == "signals":
        package_names = [
            name
            for name in sources_by_package
            if any(is_review_signal(signal) for signal in signals_by_package[name])
        ]
    else:
        package_names = list(sources_by_package)

    package_names.sort(
        key=lambda name: package_priority(
            package_by_name[name],
            signals_by_package[name],
        )
    )
    if max_dossiers > 0:
        package_names = package_names[:max_dossiers]

    dossiers: list[Dossier] = []
    for name in package_names:
        package = package_by_name[name]
        package_sources = tuple(sorted(sources_by_package[name], key=lambda source: source.path.as_posix()))
        package_signals = tuple(select_dossier_signals(signals_by_package[name], evidence_per_package))
        placeholder = Dossier(
            package=package,
            source_files=package_sources,
            signals=package_signals,
            prompt="",
        )
        prompt = build_llm_prompt(placeholder, repo_root, dossier_chars)
        dossiers.append(
            Dossier(
                package=package,
                source_files=package_sources,
                signals=package_signals,
                prompt=prompt,
            )
        )

    return dossiers


def is_review_signal(signal: Finding) -> bool:
    return SEVERITY_RANK[signal.severity] >= SEVERITY_RANK["medium"]


def package_priority(package: PackageInfo, signals: list[Finding]) -> tuple[int, int, str]:
    if not signals:
        return (0, 0, package.import_path)
    highest = max(SEVERITY_RANK[signal.severity] for signal in signals)
    review_signal_count = sum(1 for signal in signals if is_review_signal(signal))
    return (-highest, -review_signal_count, package.import_path)


def select_dossier_signals(signals: list[Finding], limit: int) -> list[Finding]:
    sorted_signals = sorted(signals, key=finding_sort_key)
    if limit <= 0:
        return sorted_signals

    review_signals = [signal for signal in sorted_signals if is_review_signal(signal)]
    low_signals = [
        signal
        for signal in sorted_signals
        if not is_review_signal(signal)
        and signal.rule not in {"external-url", "doc-url"}
    ]
    selected = review_signals + low_signals
    return selected[:limit]


def build_llm_prompt(dossier: Dossier, repo_root: Path, dossier_chars: int) -> str:
    package = dossier.package
    version = f" {package.module_version}" if package.module_version else ""
    sections = [
        "You are a security investigator auditing vendored dependency source code.",
        "",
        "Goal:",
        "- Decide whether this vendored package appears to do something it should not do.",
        "- Focus on reading/writing sensitive files, collecting secrets, unexpected external network calls, offloading data, command execution, dynamic code loading, native-code escape hatches, and privileged kernel capabilities.",
        "- Distinguish suspicious behavior from normal library capability. A package may legitimately expose HTTP, filesystem, process, platform, eBPF, perf-event, tracefs, bpffs, /proc, or /sys APIs; mark those as benign capability when appropriate.",
        "- Severity is review priority and operational security impact, not only maliciousness. Benign-but-privileged kernel capabilities should usually be medium severity so they remain visible in the default report.",
        "- Include findings for important privileged capabilities even when likely_benign is true. Use likely_benign to separate expected capability from suspicious behavior.",
        "- Do not modify files. If you inspect additional repository files, read only.",
        "- Return only a JSON object matching the requested shape.",
        "",
        "Package:",
        f"- module: {package.module_path}{version}",
        f"- import_path: {package.import_path}",
        f"- source_files: {len(dossier.source_files)}",
        f"- gathered_signals: {len(dossier.signals)}",
        "",
        "Required JSON shape:",
        json.dumps(llm_schema_example(package), indent=2),
        "",
        "File index:",
        build_file_index(dossier.source_files, repo_root),
        "",
        "Gathered evidence signals:",
        build_signal_section(dossier.signals, repo_root),
        "",
        "Relevant source excerpts:",
        build_source_excerpt_section(dossier, repo_root),
    ]
    prompt = "\n".join(sections)
    if len(prompt) <= dossier_chars:
        return prompt

    trimmed = prompt[:dossier_chars]
    return (
        trimmed
        + "\n\n[truncated dossier: prompt reached --dossier-chars limit]\n"
        + "Return JSON using only the evidence available above."
    )


def llm_schema_example(package: PackageInfo) -> dict[str, object]:
    return {
        "package": package.import_path,
        "module": package.module_path,
        "module_version": package.module_version,
        "verdict": "clean | benign_capability | needs_review | suspicious",
        "severity": "low | medium | high | critical",
        "confidence": "low | medium | high",
        "summary": "One or two sentences with the security judgment and notable capabilities.",
        "findings": [
            {
                "severity": "low | medium | high | critical",
                "category": "filesystem | network | secrets | process | native | kernel | other",
                "path": "vendor/example/file.go",
                "line": 123,
                "evidence": "short code excerpt",
                "reasoning": "why this is or is not concerning",
                "remediation": "what to verify or change next",
                "likely_benign": False,
            }
        ],
        "limitations": "Important missing context or uncertainty.",
    }


def build_file_index(sources: tuple[SourceFile, ...], repo_root: Path) -> str:
    rows: list[str] = []
    for source in sources[:200]:
        generated = " generated" if source.generated else ""
        rows.append(f"- {relative_path(source.path, repo_root)}{generated}")
    if len(sources) > 200:
        rows.append(f"- ... {len(sources) - 200} more files")
    return "\n".join(rows) if rows else "- none"


def build_signal_section(signals: tuple[Finding, ...], repo_root: Path) -> str:
    if not signals:
        return "- No suspicious static signals were gathered for this package."

    rows: list[str] = []
    for idx, signal in enumerate(signals, start=1):
        rows.extend(
            [
                f"{idx}. [{signal.severity}] {signal.rule} ({signal.category})",
                f"   path: {signal.path}:{signal.line}",
                f"   why: {signal.message}",
                f"   evidence: {signal.evidence}",
            ]
        )
        snippet = source_context(Path(repo_root, signal.path), signal.line)
        if snippet:
            rows.append("   context:")
            rows.extend(f"     {line}" for line in snippet.splitlines())
    return "\n".join(rows)


def build_source_excerpt_section(dossier: Dossier, repo_root: Path) -> str:
    selected_paths: list[Path] = []
    for signal in dossier.signals:
        path = Path(repo_root, signal.path)
        if path not in selected_paths:
            selected_paths.append(path)

    if not selected_paths:
        for source in dossier.source_files:
            if source.generated:
                continue
            selected_paths.append(source.path)
            if len(selected_paths) >= 4:
                break

    rows: list[str] = []
    for path in selected_paths[:8]:
        excerpt = source_excerpt(path)
        if not excerpt:
            continue
        rows.append(f"### {relative_path(path, repo_root)}")
        rows.append(excerpt)

    return "\n\n".join(rows) if rows else "No source excerpts available."


def source_context(path: Path, line_no: int, radius: int = 4) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    if line_no <= 0:
        return ""
    start = max(1, line_no - radius)
    end = min(len(lines), line_no + radius)
    return "\n".join(
        f"{idx:5d}: {lines[idx - 1][:240]}"
        for idx in range(start, end + 1)
    )


def source_excerpt(path: Path, max_lines: int = 120, max_chars: int = 10000) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return f"[could not read: {exc}]"

    rows: list[str] = []
    used = 0
    for idx, line in enumerate(lines[:max_lines], start=1):
        rendered = f"{idx:5d}: {line[:240]}"
        used += len(rendered) + 1
        if used > max_chars:
            rows.append("[excerpt truncated]")
            break
        rows.append(rendered)
    if len(lines) > max_lines:
        rows.append(f"[excerpt stopped after {max_lines} of {len(lines)} lines]")
    return "\n".join(rows)


def run_llm_assessments(
    dossiers: list[Dossier],
    args: argparse.Namespace,
    repo_root: Path,
) -> list[LLMAssessment]:
    if args.save_prompts:
        args.save_prompts.mkdir(parents=True, exist_ok=True)

    assessments: list[LLMAssessment] = []
    for idx, dossier in enumerate(dossiers, start=1):
        if args.save_prompts:
            prompt_name = safe_prompt_name(dossier.import_path) + ".prompt.txt"
            (args.save_prompts / prompt_name).write_text(dossier.prompt, encoding="utf-8")

        backend_name = args.llm_backend.capitalize()
        print(
            f"[vendor-audit-agent] asking {backend_name} to review "
            f"{idx}/{len(dossiers)}: {dossier.import_path}",
            file=sys.stderr,
        )
        if args.llm_backend == "codex":
            assessments.append(run_codex_assessment(dossier, args, repo_root))
        elif args.llm_backend == "claude":
            assessments.append(run_claude_assessment(dossier, args, repo_root))
        else:
            assessments.append(
                LLMAssessment.error_result(
                    dossier.package,
                    f"unsupported LLM backend `{args.llm_backend}`",
                )
            )

    return assessments


def safe_prompt_name(import_path: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", import_path).strip("_") or "package"


def run_codex_assessment(
    dossier: Dossier,
    args: argparse.Namespace,
    repo_root: Path,
) -> LLMAssessment:
    with tempfile.TemporaryDirectory(prefix="vendor-audit-agent-") as tmp:
        tmp_path = Path(tmp)
        output_path = tmp_path / "last-message.json"
        schema_path = tmp_path / "assessment-schema.json"
        schema_path.write_text(json.dumps(llm_output_schema(), indent=2), encoding="utf-8")

        cmd = [
            args.codex_bin,
            "exec",
            "--cd",
            str(repo_root),
            "--sandbox",
            "read-only",
            "--ephemeral",
            "--output-schema",
            str(schema_path),
            "--output-last-message",
            str(output_path),
            "-",
        ]
        if args.model:
            cmd[2:2] = ["--model", args.model]
        if args.profile:
            cmd[2:2] = ["--profile", args.profile]

        try:
            proc = subprocess.run(
                cmd,
                input=dossier.prompt,
                text=True,
                capture_output=True,
                timeout=args.llm_timeout,
                check=False,
            )
        except FileNotFoundError:
            return LLMAssessment.error_result(
                dossier.package,
                f"could not find Codex executable `{args.codex_bin}`",
            )
        except subprocess.TimeoutExpired as exc:
            raw = (exc.stdout or "") + (exc.stderr or "")
            return LLMAssessment.error_result(
                dossier.package,
                f"Codex timed out after {args.llm_timeout}s",
                raw_response=raw,
            )

        raw_response = ""
        if output_path.exists():
            raw_response = output_path.read_text(encoding="utf-8", errors="replace")
        if not raw_response.strip():
            raw_response = "\n".join(part for part in (proc.stdout, proc.stderr) if part)

        if proc.returncode != 0:
            return LLMAssessment.error_result(
                dossier.package,
                f"Codex exited with status {proc.returncode}",
                raw_response=raw_response,
            )

        try:
            data = extract_assessment_json(raw_response)
        except ValueError as exc:
            return LLMAssessment.error_result(
                dossier.package,
                str(exc),
                raw_response=raw_response,
            )

        return LLMAssessment.from_dict(data, dossier.package, raw_response)


def run_claude_assessment(
    dossier: Dossier,
    args: argparse.Namespace,
    repo_root: Path,
) -> LLMAssessment:
    schema = json.dumps(llm_output_schema(), separators=(",", ":"))
    cmd = [
        args.claude_bin,
        "-p",
        "--output-format",
        "json",
        "--input-format",
        "text",
        "--permission-mode",
        "dontAsk",
        "--no-session-persistence",
        "--json-schema",
        schema,
    ]
    if args.claude_tools:
        cmd.extend(["--tools", args.claude_tools])
    else:
        cmd.extend(["--tools", ""])
    if args.model:
        cmd.extend(["--model", args.model])

    try:
        proc = subprocess.run(
            cmd,
            input=dossier.prompt,
            text=True,
            capture_output=True,
            timeout=args.llm_timeout,
            check=False,
            cwd=repo_root,
        )
    except FileNotFoundError:
        return LLMAssessment.error_result(
            dossier.package,
            f"could not find Claude executable `{args.claude_bin}`",
        )
    except subprocess.TimeoutExpired as exc:
        raw = (exc.stdout or "") + (exc.stderr or "")
        return LLMAssessment.error_result(
            dossier.package,
            f"Claude timed out after {args.llm_timeout}s",
            raw_response=raw,
        )

    raw_response = "\n".join(part for part in (proc.stdout, proc.stderr) if part)

    if proc.returncode != 0:
        return LLMAssessment.error_result(
            dossier.package,
            f"Claude exited with status {proc.returncode}",
            raw_response=raw_response,
        )

    try:
        data = extract_assessment_json(raw_response)
    except ValueError as exc:
        return LLMAssessment.error_result(
            dossier.package,
            str(exc),
            raw_response=raw_response,
        )

    return LLMAssessment.from_dict(data, dossier.package, raw_response)


def llm_output_schema() -> dict[str, object]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "package",
            "module",
            "module_version",
            "verdict",
            "severity",
            "confidence",
            "summary",
            "findings",
            "limitations",
        ],
        "properties": {
            "package": {"type": "string"},
            "module": {"type": "string"},
            "module_version": {"type": "string"},
            "verdict": {"type": "string", "enum": list(LLM_VERDICTS[:-1])},
            "severity": {"type": "string", "enum": list(SEVERITIES)},
            "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
            "summary": {"type": "string"},
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "severity",
                        "category",
                        "path",
                        "line",
                        "evidence",
                        "reasoning",
                        "remediation",
                        "likely_benign",
                    ],
                    "properties": {
                        "severity": {"type": "string", "enum": list(SEVERITIES)},
                        "category": {"type": "string"},
                        "path": {"type": "string"},
                        "line": {"type": "integer"},
                        "evidence": {"type": "string"},
                        "reasoning": {"type": "string"},
                        "remediation": {"type": "string"},
                        "likely_benign": {"type": "boolean"},
                    },
                },
            },
            "limitations": {"type": "string"},
        },
    }


def extract_assessment_json(raw_response: str) -> dict[str, object]:
    raw_response = raw_response.strip()
    if not raw_response:
        raise ValueError("LLM returned an empty response")

    try:
        parsed = json.loads(raw_response)
    except json.JSONDecodeError:
        parsed = None

    if isinstance(parsed, dict):
        direct = assessment_object_from_parsed(parsed)
        if direct is not None:
            return direct

    return extract_json_object(raw_response)


def assessment_object_from_parsed(data: dict[str, object]) -> dict[str, object] | None:
    if "verdict" in data and "findings" in data:
        return data

    structured_output = data.get("structured_output")
    if isinstance(structured_output, dict):
        nested = assessment_object_from_parsed(structured_output)
        if nested is not None:
            return nested
    if isinstance(structured_output, str):
        try:
            return extract_assessment_json(structured_output)
        except ValueError:
            return None

    result = data.get("result")
    if isinstance(result, dict):
        nested = assessment_object_from_parsed(result)
        if nested is not None:
            return nested
    if isinstance(result, str):
        try:
            return extract_assessment_json(result)
        except ValueError:
            return None

    message = data.get("message")
    if isinstance(message, dict):
        nested = assessment_object_from_parsed(message)
        if nested is not None:
            return nested
    if isinstance(message, str):
        try:
            return extract_assessment_json(message)
        except ValueError:
            return None

    content = data.get("content")
    if isinstance(content, list):
        for item in content:
            if not isinstance(item, dict):
                continue
            text = item.get("text")
            if isinstance(text, str):
                try:
                    return extract_assessment_json(text)
                except ValueError:
                    continue

    return None


def extract_json_object(raw_response: str) -> dict[str, object]:
    raw_response = raw_response.strip()
    if not raw_response:
        raise ValueError("LLM returned an empty response")

    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw_response, re.DOTALL)
    if fence:
        raw_response = fence.group(1)
    else:
        start = raw_response.find("{")
        end = raw_response.rfind("}")
        if start == -1 or end == -1 or end < start:
            raise ValueError("LLM response did not contain a JSON object")
        raw_response = raw_response[start : end + 1]

    try:
        data = json.loads(raw_response)
    except json.JSONDecodeError as exc:
        raise ValueError(f"LLM response was not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("LLM response JSON was not an object")
    return data


def print_llm_report(
    assessments: list[LLMAssessment],
    source_count: int,
    module_count: int,
    package_count: int,
    dossier_count: int,
    signal_count: int,
    min_severity: str,
    max_findings: int,
) -> None:
    display = [
        assessment
        for assessment in assessments
        if assessment_matches_min_severity(assessment, min_severity)
    ]
    display.sort(key=assessment_sort_key)

    print("Vendor LLM audit agent report")
    print("=============================")
    print(f"Indexed modules:    {module_count}")
    print(f"Indexed packages:   {package_count}")
    print(f"Indexed files:      {source_count}")
    print(f"Gathered signals:   {signal_count}")
    print(f"LLM dossiers:       {dossier_count}")
    print(f"LLM assessments:    {len(assessments)}")
    print(f"Displayed:          {len(display)} at {min_severity}+ or error")
    print()

    print_counter("By LLM verdict", Counter(assessment.verdict for assessment in assessments), LLM_VERDICTS)
    print_counter("By LLM severity", Counter(assessment.severity for assessment in assessments), SEVERITIES)

    finding_counter = Counter(
        finding.category
        for assessment in assessments
        for finding in assessment.findings
    )
    print_counter("By LLM finding category", finding_counter)

    if max_findings > 0:
        display = display[:max_findings]

    print("Assessments")
    print("-----------")
    if not display:
        print(f"No LLM assessments at {min_severity}+.")
        return

    for assessment in display:
        version = f" {assessment.module_version}" if assessment.module_version else ""
        print(
            f"[{assessment.severity.upper()}] {assessment.verdict} "
            f"{assessment.package}"
        )
        print(f"  module:     {assessment.module}{version}")
        print(f"  confidence: {assessment.confidence}")
        print(f"  summary:    {assessment.summary}")
        if assessment.error:
            print(f"  error:      {assessment.error}")
        if assessment.limitations:
            print(f"  limits:     {assessment.limitations}")
        for finding in assessment.findings:
            print(
                f"  - [{finding.severity}] {finding.category} "
                f"{finding.path}:{finding.line}"
            )
            print(f"    evidence:    {finding.evidence}")
            print(f"    reasoning:   {finding.reasoning}")
            print(f"    remediation: {finding.remediation}")
            print(f"    likely benign: {str(finding.likely_benign).lower()}")
        print()

    undisplayed = len(
        [
            assessment
            for assessment in assessments
            if assessment_matches_min_severity(assessment, min_severity)
        ]
    ) - len(display)
    if undisplayed > 0:
        print(f"... {undisplayed} more assessments hidden by --max-findings")


def assessment_matches_min_severity(assessment: LLMAssessment, min_severity: str) -> bool:
    if assessment.verdict == "error":
        return True
    threshold = SEVERITY_RANK[min_severity]
    if SEVERITY_RANK[assessment.severity] >= threshold:
        return True
    return any(SEVERITY_RANK[finding.severity] >= threshold for finding in assessment.findings)


def assessment_sort_key(assessment: LLMAssessment) -> tuple[int, int, str]:
    verdict_rank = {
        "error": 0,
        "suspicious": 1,
        "needs_review": 2,
        "benign_capability": 3,
        "clean": 4,
    }.get(assessment.verdict, 5)
    return (-SEVERITY_RANK[assessment.severity], verdict_rank, assessment.package)


def should_fail_assessments(assessments: list[LLMAssessment], fail_on: str) -> bool:
    if fail_on == "none":
        return False
    threshold = SEVERITY_RANK[fail_on]
    return any(
        SEVERITY_RANK[assessment.severity] >= threshold
        or any(SEVERITY_RANK[finding.severity] >= threshold for finding in assessment.findings)
        for assessment in assessments
    )


def print_text_report(
    findings: list[Finding],
    source_count: int,
    module_count: int,
    package_count: int,
    min_severity: str,
    max_findings: int,
) -> None:
    display = [
        finding
        for finding in findings
        if SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[min_severity]
    ]
    display.sort(key=finding_sort_key)

    print("Vendor evidence-gathering report")
    print("================================")
    print(f"Scanned modules:  {module_count}")
    print(f"Scanned packages: {package_count}")
    print(f"Scanned files:    {source_count}")
    print(f"Findings:         {len(findings)} total, {len(display)} at {min_severity}+")
    print()

    print_counter("By severity", Counter(finding.severity for finding in findings), SEVERITIES)
    print_counter("By category", Counter(finding.category for finding in findings))
    print_counter("By rule", Counter(finding.rule for finding in findings))

    print(f"Top modules at {min_severity}+")
    print("----------------------")
    module_counts = Counter(finding.module for finding in display)
    if module_counts:
        for module, count in module_counts.most_common(20):
            print(f"{count:5d}  {module}")
    else:
        print("No findings.")
    print()

    if max_findings > 0:
        display = display[:max_findings]

    print("Findings")
    print("--------")
    if not display:
        print(f"No findings at {min_severity}+.")
        return

    for finding in display:
        version = f" {finding.module_version}" if finding.module_version else ""
        print(
            f"[{finding.severity.upper()}] {finding.rule} ({finding.category}) "
            f"{finding.path}:{finding.line}"
        )
        print(f"  module:  {finding.module}{version}")
        if finding.package != finding.module:
            print(f"  package: {finding.package}")
        print(f"  why:     {finding.message}")
        print(f"  code:    {finding.evidence}")
        print()

    undisplayed = len(
        [
            finding
            for finding in findings
            if SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[min_severity]
        ]
    ) - len(display)
    if undisplayed > 0:
        print(f"... {undisplayed} more findings hidden by --max-findings")


def print_counter(title: str, counter: Counter[str], order: Iterable[str] | None = None) -> None:
    print(title)
    print("-" * len(title))
    if not counter:
        print("none")
        print()
        return

    if order is None:
        rows = counter.most_common()
    else:
        rows = [(key, counter[key]) for key in order if counter[key]]
    for key, count in rows:
        print(f"{count:5d}  {key}")
    print()


def finding_sort_key(finding: Finding) -> tuple[int, str, str, int, str]:
    return (
        -SEVERITY_RANK[finding.severity],
        finding.module,
        finding.path,
        finding.line,
        finding.rule,
    )


def should_fail(findings: list[Finding], fail_on: str) -> bool:
    if fail_on == "none":
        return False
    threshold = SEVERITY_RANK[fail_on]
    return any(SEVERITY_RANK[finding.severity] >= threshold for finding in findings)


def main() -> int:
    args = parse_args()
    repo_root = Path.cwd()
    vendor_dir = args.vendor_dir
    if not vendor_dir.is_absolute():
        vendor_dir = repo_root / vendor_dir

    try:
        modules, packages = parse_modules(vendor_dir)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    sources = collect_source_files(
        vendor_dir=vendor_dir,
        modules=modules,
        packages=packages,
        package_filters=args.package,
        include_tests=args.include_tests,
        include_non_runtime=args.include_non_runtime,
        skip_generated=args.skip_generated,
    )

    findings: list[Finding] = []
    for source in sources:
        findings.extend(scan_file(source, repo_root))

    findings.sort(key=finding_sort_key)

    dossiers = build_dossiers(
        sources=sources,
        signals=findings,
        repo_root=repo_root,
        review_scope=args.review_scope,
        max_dossiers=args.llm_max_dossiers,
        evidence_per_package=args.evidence_per_package,
        dossier_chars=args.dossier_chars,
    )

    if args.llm_backend == "none":
        if args.json:
            report = {
                "mode": "evidence-only",
                "vendor_dir": relative_path(vendor_dir, repo_root),
                "scanned_modules": len({source.package.module_path for source in sources}),
                "scanned_packages": len({source.package.import_path for source in sources}),
                "scanned_files": len(sources),
                "dossier_count": len(dossiers),
                "finding_count": len(findings),
                "counts": {
                    "severity": dict(Counter(finding.severity for finding in findings)),
                    "category": dict(Counter(finding.category for finding in findings)),
                    "rule": dict(Counter(finding.rule for finding in findings)),
                },
                "findings": [finding.as_dict() for finding in findings],
            }
            json.dump(report, sys.stdout, indent=2, sort_keys=True)
            print()
        else:
            print_text_report(
                findings=findings,
                source_count=len(sources),
                module_count=len({source.package.module_path for source in sources}),
                package_count=len({source.package.import_path for source in sources}),
                min_severity=args.min_severity,
                max_findings=args.max_findings,
            )
        return 2 if should_fail(findings, args.fail_on) else 0

    assessments = run_llm_assessments(dossiers, args, repo_root)

    if args.json:
        report = {
            "mode": "llm",
            "llm_backend": args.llm_backend,
            "vendor_dir": relative_path(vendor_dir, repo_root),
            "scanned_modules": len({source.package.module_path for source in sources}),
            "scanned_packages": len({source.package.import_path for source in sources}),
            "scanned_files": len(sources),
            "gathered_signal_count": len(findings),
            "dossier_count": len(dossiers),
            "assessment_count": len(assessments),
            "counts": {
                "llm_verdict": dict(Counter(assessment.verdict for assessment in assessments)),
                "llm_severity": dict(Counter(assessment.severity for assessment in assessments)),
                "signal_severity": dict(Counter(finding.severity for finding in findings)),
                "signal_category": dict(Counter(finding.category for finding in findings)),
                "signal_rule": dict(Counter(finding.rule for finding in findings)),
            },
            "assessments": [assessment.as_dict() for assessment in assessments],
        }
        json.dump(report, sys.stdout, indent=2, sort_keys=True)
        print()
    else:
        print_llm_report(
            assessments=assessments,
            source_count=len(sources),
            module_count=len({source.package.module_path for source in sources}),
            package_count=len({source.package.import_path for source in sources}),
            dossier_count=len(dossiers),
            signal_count=len(findings),
            min_severity=args.min_severity,
            max_findings=args.max_findings,
        )

    return 2 if should_fail_assessments(assessments, args.fail_on) else 0


if __name__ == "__main__":
    sys.exit(main())
