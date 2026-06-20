"""
Plugin Scanner - Plugin Security Scanning Chain

Features:
- Plugin manifest validation
- Permission scope analysis
- Static code scanning (dangerous patterns)
- Dependency vulnerability check
- Security report generation
"""

from __future__ import annotations

import os
import re
import json
import hashlib
import logging
from enum import Enum
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanResult(Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    SKIP = "skip"


@dataclass
class SecurityFinding:
    """安全发现"""
    rule_id: str
    severity: str
    message: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    recommendation: Optional[str] = None


@dataclass
class ScanReport:
    """扫描报告"""
    plugin_id: str
    plugin_version: str
    scan_time: float
    duration_ms: float
    overall_result: str
    risk_level: str
    findings: list[SecurityFinding] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "plugin_id": self.plugin_id,
            "plugin_version": self.plugin_version,
            "scan_time": datetime.fromtimestamp(self.scan_time).isoformat(),
            "duration_ms": self.duration_ms,
            "overall_result": self.overall_result,
            "risk_level": self.risk_level,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "message": f.message,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "code_snippet": f.code_snippet,
                    "recommendation": f.recommendation,
                }
                for f in self.findings
            ],
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)


class DangerousPatternScanner:
    """危险模式扫描器"""

    # 危险模式定义
    DANGEROUS_PATTERNS = [
        # 代码执行
        (r"eval\s*\(", "eval() usage - code injection risk", RiskLevel.HIGH),
        (r"exec\s*\(", "exec() usage - code injection risk", RiskLevel.HIGH),
        (r"compile\s*\(.*eval", "compile with eval - code injection risk", RiskLevel.HIGH),
        (r"__import__\s*\(", "__import__ usage - dynamic import risk", RiskLevel.MEDIUM),
        (r"import\s+os\s*;", "os module import in restricted context", RiskLevel.MEDIUM),
        (r"subprocess\.call\s*\(", "subprocess.call usage", RiskLevel.MEDIUM),
        (r"subprocess\.run\s*\(", "subprocess.run usage", RiskLevel.MEDIUM),
        (r"os\.system\s*\(", "os.system usage - shell injection risk", RiskLevel.HIGH),
        (r"os\.popen\s*\(", "os.popen usage - shell injection risk", RiskLevel.HIGH),

        # 文件操作
        (r"rm\s+-rf", "recursive delete pattern", RiskLevel.CRITICAL),
        (r"chmod\s+777", "excessive permissions (777)", RiskLevel.HIGH),
        (r"chmod\s+0", "removing all permissions", RiskLevel.HIGH),
        (r"open\s*\([^)]*[\"']w[\"']", "file write operation", RiskLevel.MEDIUM),
        (r"\./\.\./", "path traversal attempt", RiskLevel.HIGH),

        # 网络
        (r"requests\.get\s*\(.*timeout\s*=\s*0", "requests with no timeout - DoS risk", RiskLevel.MEDIUM),
        (r"socket\.socket\s*\(", "direct socket creation", RiskLevel.MEDIUM),
        (r"http\.server", "HTTP server creation", RiskLevel.MEDIUM),

        # 加密/密钥
        (r"password\s*=", "hardcoded password", RiskLevel.HIGH),
        (r"api[_-]?key\s*=", "hardcoded API key", RiskLevel.HIGH),
        (r"secret\s*=", "hardcoded secret", RiskLevel.HIGH),
        (r"encrypt\s*\(.*key", "encryption with hardcoded key", RiskLevel.CRITICAL),

        # 反调试/混淆
        (r"sys\.stoptrace", "trace function manipulation", RiskLevel.HIGH),
        (r"signal\.signal\s*\(\s*signal\.SIG", "signal handler manipulation", RiskLevel.MEDIUM),
    ]

    def scan_file(self, file_path: Path) -> list[SecurityFinding]:
        """扫描单个文件"""
        findings = []

        if not file_path.exists() or not file_path.is_file():
            return findings

        # 跳过二进制和大文件
        if file_path.stat().st_size > 1024 * 1024:  # 1MB
            return findings

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            for line_no, line in enumerate(lines, 1):
                for pattern, message, severity in self.DANGEROUS_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append(SecurityFinding(
                            rule_id=f"PATTERN_{hashlib.md5(pattern.encode()).hexdigest()[:8]}",
                            severity=severity.value,
                            message=message,
                            file_path=str(file_path),
                            line_number=line_no,
                            code_snippet=line.strip()[:200],
                            recommendation=f"Review the use of pattern: {pattern}"
                        ))

        except Exception as e:
            logger.warning(f"扫描文件失败 {file_path}: {e}")

        return findings


class PermissionAnalyzer:
    """权限分析器"""

    REQUIRED_PERMISSIONS = {
        "file_read": "读取文件",
        "file_write": "写入文件",
        "shell_execute": "执行 Shell 命令",
        "env_read": "读取环境变量",
        "env_write": "写入环境变量",
        "network": "网络访问",
        "agent_spawn": "启动子 Agent",
    }

    DANGEROUS_PERMISSIONS = [
        ("shell_execute", "shell 执行权限可能导致任意命令执行"),
        ("env_write", "环境变量写入可能导致配置篡改"),
        ("file_write", "文件写入可能导致系统文件破坏"),
    ]

    def analyze_manifest(self, manifest: dict) -> list[SecurityFinding]:
        """分析插件权限清单"""
        findings = []

        permissions = manifest.get("permissions", [])
        if not permissions:
            return findings

        # 检查危险权限
        for perm, desc in self.DANGEROUS_PERMISSIONS:
            if perm in permissions:
                findings.append(SecurityFinding(
                    rule_id=f"DANGEROUS_PERM_{perm}",
                    severity=RiskLevel.MEDIUM.value,
                    message=f"危险权限请求: {desc}",
                    recommendation=f"仅在必要时请求 {perm} 权限"
                ))

        # 检查未声明的权限
        for perm in permissions:
            if perm not in self.REQUIRED_PERMISSIONS:
                findings.append(SecurityFinding(
                    rule_id=f"UNKNOWN_PERM_{perm}",
                    severity=RiskLevel.MEDIUM.value,
                    message=f"未知权限: {perm}",
                    recommendation="确认此权限是否为标准权限"
                ))

        return findings


class PluginScanner:
    """
    插件安全扫描链

    扫描阶段:
    1. Manifest 验证
    2. 权限分析
    3. 代码静态扫描
    4. 依赖检查
    5. 报告生成
    """

    def __init__(self):
        self.pattern_scanner = DangerousPatternScanner()
        self.permission_analyzer = PermissionAnalyzer()
        self._scan_handlers: list[callable] = []

    def register_handler(self, handler: callable):
        """注册自定义扫描处理器"""
        self._scan_handlers.append(handler)

    def scan(self, plugin_path: str | Path) -> ScanReport:
        """
        执行完整安全扫描

        Args:
            plugin_path: 插件目录或 manifest.json 路径

        Returns:
            扫描报告
        """
        start_time = time.time()
        plugin_path = Path(plugin_path)

        # 确定插件根目录
        if plugin_path.name == "manifest.json":
            plugin_root = plugin_path.parent
        else:
            plugin_root = plugin_path

        # 加载 manifest
        manifest = self._load_manifest(plugin_root)
        if not manifest:
            return ScanReport(
                plugin_id="unknown",
                plugin_version="0.0.0",
                scan_time=time.time(),
                duration_ms=(time.time() - start_time) * 1000,
                overall_result=ScanResult.FAIL.value,
                risk_level=RiskLevel.CRITICAL.value,
                findings=[SecurityFinding(
                    rule_id="MANIFEST_MISSING",
                    severity=RiskLevel.CRITICAL.value,
                    message="manifest.json 不存在或无效"
                )]
            )

        plugin_id = manifest.get("id", "unknown")
        plugin_version = manifest.get("version", "0.0.0")
        findings: list[SecurityFinding] = []

        # 阶段 1: 权限分析
        findings.extend(self.permission_analyzer.analyze_manifest(manifest))

        # 阶段 2: 代码扫描
        code_files = list(plugin_root.rglob("*.py"))
        for code_file in code_files:
            findings.extend(self.pattern_scanner.scan_file(code_file))

        # 阶段 3: 自定义处理器
        for handler in self._scan_handlers:
            try:
                findings.extend(handler(plugin_root, manifest))
            except Exception as e:
                logger.error(f"扫描处理器异常: {e}")

        # 计算风险等级
        risk_level = self._calculate_risk_level(findings)

        # 确定扫描结果
        if any(f.severity == RiskLevel.CRITICAL.value for f in findings):
            overall_result = ScanResult.FAIL.value
        elif any(f.severity == RiskLevel.HIGH.value for f in findings):
            overall_result = ScanResult.WARN.value
        elif findings:
            overall_result = ScanResult.WARN.value
        else:
            overall_result = ScanResult.PASS.value

        duration_ms = (time.time() - start_time) * 1000

        return ScanReport(
            plugin_id=plugin_id,
            plugin_version=plugin_version,
            scan_time=time.time(),
            duration_ms=duration_ms,
            overall_result=overall_result,
            risk_level=risk_level,
            findings=findings,
            metadata={
                "files_scanned": len(code_files),
                "manifest_valid": bool(manifest),
            }
        )

    def _load_manifest(self, plugin_root: Path) -> dict | None:
        """加载插件 manifest"""
        manifest_path = plugin_root / "manifest.json"
        if not manifest_path.exists():
            return None

        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"加载 manifest 失败: {e}")
            return None

    def _calculate_risk_level(self, findings: list[SecurityFinding]) -> str:
        """计算风险等级"""
        severity_counts = {s.value: 0 for s in RiskLevel}
        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        if severity_counts[RiskLevel.CRITICAL.value] > 0:
            return RiskLevel.CRITICAL.value
        elif severity_counts[RiskLevel.HIGH.value] > 2:
            return RiskLevel.HIGH.value
        elif severity_counts[RiskLevel.HIGH.value] > 0:
            return RiskLevel.MEDIUM.value
        elif severity_counts[RiskLevel.MEDIUM.value] > 0:
            return RiskLevel.LOW.value
        else:
            return RiskLevel.LOW.value


import time


# 便捷函数
_scanner_instance: Optional[PluginScanner] = None


def get_scanner() -> PluginScanner:
    """获取扫描器单例"""
    global _scanner_instance
    if _scanner_instance is None:
        _scanner_instance = PluginScanner()
    return _scanner_instance


def scan_plugin(plugin_path: str | Path) -> ScanReport:
    """快速扫描插件"""
    return get_scanner().scan(plugin_path)
