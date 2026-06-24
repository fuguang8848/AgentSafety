"""
Informed Consent Module for AgentSafety

梁文峰开源理念：
- 闭源 = "我对用户负责"
- 开源 = "用户对自己负责"

BLOCK 模式剥夺了用户的"知情同意权"：
- 用户不知道为何被阻止
- 用户无法选择接受风险继续执行
- 用户无法自定义安全策略

本模块实现"用户知情同意"机制：
1. 完整披露决策理由
2. 用户可以选择"接受风险继续"
3. 用户可以自定义规则和阈值
4. 审计日志完整记录用户选择
"""

from __future__ import annotations

import json
import time
import hashlib
from typing import Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import logging

logger = logging.getLogger(__name__)


class ConsentLevel(Enum):
    """用户同意等级"""
    UNASKED = "unasked"           # 尚未询问
    INFORMED = "informed"          # 已告知风险
    ACCEPTED = "accepted"          # 用户接受风险
    REJECTED = "rejected"          # 用户拒绝
    TIMEOUT = "timeout"            # 超时未响应


@dataclass
class RiskDisclosure:
    """风险披露完整信息"""
    operation: str                 # 操作描述
    causal_explanation: str        # 因果解释（为什么危险）
    pattern_explanation: str      # 模式解释（匹配了什么规则）
    potential_consequences: str    # 潜在后果
    alternative_suggestion: str | None  # 安全替代方案
    estimated_impact: str          # 影响范围评估
    reversibility: str            # 可逆性评估
    user_accepts: bool = False    # 用户是否接受


@dataclass
class ConsentRecord:
    """用户同意记录（审计用）"""
    timestamp: float
    operation_hash: str            # 操作哈希（脱敏）
    risk_level: str
    consent_level: ConsentLevel
    disclosure: dict               # 风险披露摘要
    user_id: str | None            # 用户标识（可选）
    session_id: str                # 会话ID
    reason: str | None             # 用户理由（可选）


class InformedConsentManager:
    """
    知情同意管理器
    
    设计原则：
    1. 透明度：完整披露决策理由
    2. 选择权：用户可以接受风险继续
    3. 可追溯：所有选择都被审计
    4. 可配置：用户可以自定义策略
    """
    
    def __init__(self, audit_dir: str | None = None):
        self._audit_dir = Path(audit_dir) if audit_dir else Path.home() / ".agent-safety"
        self._audit_dir.mkdir(parents=True, exist_ok=True)
        self._consent_file = self._audit_dir / "consent_log.jsonl"
        
        # 用户自定义规则（覆盖默认规则）
        self._user_rules: dict = {}
        
        # 用户自定义阈值
        self._user_thresholds: dict = {
            "block_threshold": 0.9,     # 高于此分数才 BLOCK
            "warn_threshold": 0.6,     # 高于此分数 WARN
            "auto_block_critical": True,  # CRITICAL 操作是否自动 BLOCK
        }
        
        # 同意回调（用于请求用户确认）
        self._consent_callback: Callable[[RiskDisclosure], ConsentLevel] | None = None
        
        # 审计记录
        self._consent_history: list[ConsentRecord] = []
        
    def set_consent_callback(self, callback: Callable[[RiskDisclosure], ConsentLevel]):
        """设置用户确认回调"""
        self._consent_callback = callback
        
    def update_thresholds(
        self,
        block_threshold: float | None = None,
        warn_threshold: float | None = None,
        auto_block_critical: bool | None = None
    ):
        """用户自定义阈值"""
        if block_threshold is not None:
            self._user_thresholds["block_threshold"] = max(0.0, min(1.0, block_threshold))
        if warn_threshold is not None:
            self._user_thresholds["warn_threshold"] = max(0.0, min(1.0, warn_threshold))
        if auto_block_critical is not None:
            self._user_thresholds["auto_block_critical"] = auto_block_critical
            
    def add_user_rule(self, rule_id: str, decision: str, condition: dict):
        """
        用户添加自定义规则。
        
        用户规则优先于系统规则。
        用户可以定义自己的"我接受这个风险"规则。
        """
        self._user_rules[rule_id] = {
            "decision": decision,  # "ALLOW" | "WARN" | "BLOCK" | "ASK"
            "condition": condition,
        }
        
    def remove_user_rule(self, rule_id: str):
        """移除用户规则"""
        self._user_rules.pop(rule_id, None)
        
    def get_disclosure(self, operation: str, causal: str, pattern: str, details: dict) -> RiskDisclosure:
        """生成完整的风险披露"""
        
        # 评估潜在后果
        consequences = self._assess_consequences(operation, details)
        
        # 建议替代方案
        alternative = self._suggest_alternative(operation, details)
        
        # 评估影响范围
        impact = self._assess_impact(operation, details)
        
        # 评估可逆性
        reversibility = self._assess_reversibility(operation, details)
        
        return RiskDisclosure(
            operation=operation,
            causal_explanation=causal,
            pattern_explanation=pattern,
            potential_consequences=consequences,
            alternative_suggestion=alternative,
            estimated_impact=impact,
            reversibility=reversibility,
        )
        
    def request_consent(
        self,
        operation: str,
        causal: str,
        pattern: str,
        details: dict,
        session_id: str,
        user_id: str | None = None
    ) -> tuple[ConsentLevel, ConsentRecord]:
        """
        请求用户知情同意。
        
        Returns:
            (consent_level, consent_record)
        """
        disclosure = self.get_disclosure(operation, causal, pattern, details)
        
        # 检查是否有用户规则覆盖
        override_decision = self._check_user_rules(operation, details)
        if override_decision == "ALLOW":
            record = self._create_record(
                disclosure, ConsentLevel.ACCEPTED, session_id, user_id,
                reason="用户规则覆盖：允许此操作"
            )
            return ConsentLevel.ACCEPTED, record
            
        elif override_decision == "BLOCK":
            record = self._create_record(
                disclosure, ConsentLevel.REJECTED, session_id, user_id,
                reason="用户规则覆盖：阻止此操作"
            )
            return ConsentLevel.REJECTED, record
        
        # 需要询问用户
        if self._consent_callback:
            consent = self._consent_callback(disclosure)
        else:
            # 没有回调，默认拒绝（保守策略）
            consent = ConsentLevel.REJECTED
            
        record = self._create_record(
            disclosure, consent, session_id, user_id
        )
        
        return consent, record
        
    def _check_user_rules(self, operation: str, details: dict) -> str | None:
        """检查用户规则"""
        for rule_id, rule in self._user_rules.items():
            if self._matches_condition(rule["condition"], operation, details):
                return rule["decision"]
        return None
        
    def _matches_condition(self, condition: dict, operation: str, details: dict) -> bool:
        """检查是否匹配条件"""
        if not condition:
            return True
            
        # 支持简单的条件匹配
        if "operation_type" in condition:
            if condition["operation_type"] != details.get("action_type"):
                return False
                
        if "target_pattern" in condition:
            target = details.get("target", "")
            pattern = condition["target_pattern"]
            if pattern not in target:
                return False
                
        return True
        
    def _assess_consequences(self, operation: str, details: dict) -> str:
        """评估潜在后果"""
        cmd = details.get("cmd", "") or ""
        target = details.get("target", "") or ""
        
        if "rm -rf" in cmd or "rm -r" in cmd:
            return "数据永久丢失，无法恢复。影响范围取决于被删除的文件。"
        elif ".ssh" in target or "id_rsa" in target:
            return "SSH 凭证泄露，攻击者可能获得系统访问权限。"
        elif "/etc/shadow" in target:
            return "密码文件泄露，可能导致所有用户密码被破解。"
        elif "curl | sh" in cmd:
            return "远程代码执行，攻击者可在系统上执行任意命令。"
        elif "chmod 777" in cmd:
            return "权限开放可能导致未授权访问和数据泄露。"
        else:
            return "可能导致系统不稳定、数据丢失或安全风险。"
            
    def _suggest_alternative(self, operation: str, details: dict) -> str | None:
        """建议安全的替代方案"""
        cmd = details.get("cmd", "") or ""
        target = details.get("target", "") or ""
        
        if "rm -rf" in cmd and "/" in target:
            return "建议：先使用 'ls <path>' 确认目标内容，或使用 'rm -i' 逐个确认。"
        elif "curl | sh" in cmd:
            return "建议：先下载脚本检查内容，再执行。或使用包管理器安装。"
        elif "chmod 777" in cmd:
            return "建议：使用最小必要权限，如 'chmod 755' 或 'chmod 600'。"
        elif ".ssh" in target:
            return "建议：确认为何需要访问 SSH 私钥，使用 SSH Agent 代替直接访问。"
        else:
            return None
            
    def _assess_impact(self, operation: str, details: dict) -> str:
        """评估影响范围"""
        cmd = details.get("cmd", "") or ""
        target = details.get("target", "") or ""
        
        if cmd.startswith("rm -rf /") or "rm -rf /*" in cmd:
            return "系统级影响：可能导致系统无法启动"
        elif "/home" in target:
            return "用户级影响：所有用户数据面临风险"
        elif "/tmp" in target:
            return "临时影响：仅影响临时文件，服务重启后可恢复"
        elif "/var" in target:
            return "服务级影响：可能影响运行中的服务"
        else:
            return "局部影响：具体范围取决于操作目标"
            
    def _assess_reversibility(self, operation: str, details: dict) -> str:
        """评估可逆性"""
        cmd = details.get("cmd", "") or ""
        
        if "rm" in cmd:
            return "不可逆：删除操作无法撤销，除非有备份"
        elif "chmod" in cmd:
            return "可逆：可以重新设置正确的权限"
        elif "write" in operation.lower():
            return "可逆：可以编辑或回滚更改"
        elif "env_write" in operation.lower():
            return "可逆：可以重置环境变量"
        else:
            return "部分可逆：取决于具体操作"
            
    def _create_record(
        self,
        disclosure: RiskDisclosure,
        consent: ConsentLevel,
        session_id: str,
        user_id: str | None,
        reason: str | None = None
    ) -> ConsentRecord:
        """创建同意记录"""
        # 生成操作哈希（脱敏）
        op_hash = hashlib.sha256(
            f"{disclosure.operation}:{time.time()}".encode()
        ).hexdigest()[:16]
        
        record = ConsentRecord(
            timestamp=time.time(),
            operation_hash=op_hash,
            risk_level="HIGH",  # 简化版
            consent_level=consent,
            disclosure={
                "operation_preview": disclosure.operation[:50],
                "causal_explanation": disclosure.causal_explanation,
                "alternative": disclosure.alternative_suggestion,
            },
            user_id=user_id,
            session_id=session_id,
            reason=reason,
        )
        
        self._consent_history.append(record)
        self._persist_record(record)
        
        return record
        
    def _persist_record(self, record: ConsentRecord):
        """持久化同意记录"""
        try:
            with open(self._consent_file, "a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "timestamp": record.timestamp,
                    "iso_time": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "operation_hash": record.operation_hash,
                    "risk_level": record.risk_level,
                    "consent_level": record.consent_level.value,
                    "disclosure": record.disclosure,
                    "user_id": record.user_id,
                    "session_id": record.session_id,
                    "reason": record.reason,
                }, ensure_ascii=False) + "\n")
        except Exception as e:
            logger.warning(f"Failed to persist consent record: {e}")
            
    def get_consent_history(self, limit: int = 100) -> list[dict]:
        """获取同意历史"""
        return [
            {
                "timestamp": r.timestamp,
                "consent_level": r.consent_level.value,
                "operation_hash": r.operation_hash,
                "reason": r.reason,
            }
            for r in self._consent_history[-limit:]
        ]
        
    def get_user_rules(self) -> dict:
        """获取用户自定义规则"""
        return self._user_rules.copy()
        
    def get_thresholds(self) -> dict:
        """获取用户自定义阈值"""
        return self._user_thresholds.copy()


# ── 便捷函数 ────────────────────────────────────────────────────────────────


def create_consent_manager(audit_dir: str | None = None) -> InformedConsentManager:
    """创建知情同意管理器"""
    return InformedConsentManager(audit_dir=audit_dir)
