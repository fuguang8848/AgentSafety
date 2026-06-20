"""
AgentSafety Core - 核心风险评估引擎
"""

from __future__ import annotations

import time
import logging
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Callable, Awaitable
from collections import defaultdict

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """风险等级：CRITICAL > HIGH > MEDIUM > LOW > NONE"""
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self):
        return self.name


class ActionType(Enum):
    """可监控的 Action 类型"""
    # 文件操作
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_DELETE = "file_delete"
    FILE_EXECUTE = "file_execute"
    # 网络操作
    HTTP_REQUEST = "http_request"
    DNS_LOOKUP = "dns_lookup"
    # 系统操作
    SHELL_EXECUTE = "shell_execute"
    ENV_READ = "env_read"
    ENV_WRITE = "env_write"
    # 数据操作
    DATA_DELETE = "data_delete"
    DATA_EXPORT = "data_export"
    # Agent 协作
    AGENT_SPAWN = "agent_spawn"
    AGENT_MESSAGE = "agent_message"
    # 未知
    UNKNOWN = "unknown"


@dataclass
class SafetyAction:
    """被监控的 Action"""
    action_id: str                    # 唯一标识
    action_type: ActionType           # Action 类型
    agent_id: str                     # 发起者 Agent ID
    timestamp: float = field(default_factory=time.time)
    details: dict = field(default_factory=dict)  # 原始参数
    tool_name: Optional[str] = None   # 调用的工具名
    target: Optional[str] = None      # 操作目标（文件路径/URL等）
    dry_run: bool = False             # 是否为试运行

    @property
    def risk_score(self) -> float:
        """基础风险评分：基于 ActionType"""
        scores = {
            ActionType.FILE_DELETE: 0.8,
            ActionType.FILE_EXECUTE: 0.9,
            ActionType.SHELL_EXECUTE: 0.9,
            ActionType.HTTP_REQUEST: 0.5,
            ActionType.DATA_DELETE: 0.85,
            ActionType.DATA_EXPORT: 0.7,
            ActionType.AGENT_SPAWN: 0.4,
            ActionType.ENV_WRITE: 0.7,
            ActionType.FILE_WRITE: 0.5,
            ActionType.FILE_READ: 0.1,
            ActionType.ENV_READ: 0.1,
            ActionType.UNKNOWN: 0.5,
        }
        return scores.get(self.action_type, 0.5)


@dataclass
class SafetyDecision:
    """安全决策结果"""
    action_id: str
    risk_level: RiskLevel
    decision: str          # "ALLOW" | "WARN" | "BLOCK" | "CIRCUIT_BREAK"
    reason: str            # 决策理由
    risk_score: float      # 0.0-1.0
    matched_policies: list[str] = field(default_factory=list)
    llm_advice: Optional[str] = None  # LLM 辅助判断（可选）
    timestamp: float = field(default_factory=time.time)
    metadata: dict = field(default_factory=dict)


class PolicyRule:
    """单条策略规则"""

    def __init__(
        self,
        rule_id: str,
        name: str,
        action_type: ActionType | None,
        target_pattern: str | None,      # glob 模式，如 "*/.ssh/*"
        risk_level: RiskLevel,
        decision: str,
        reason: str,
        enabled: bool = True,
    ):
        self.rule_id = rule_id
        self.name = name
        self.action_type = action_type
        self.target_pattern = target_pattern
        self.risk_level = risk_level
        self.decision = decision
        self.reason = reason
        self.enabled = enabled

    def matches(self, action: SafetyAction) -> bool:
        """检查规则是否匹配"""
        if not self.enabled:
            return False
        if self.action_type is not None and action.action_type != self.action_type:
            return False
        if self.target_pattern:
            import fnmatch
            # Match 1: action.target (primary field, e.g. file path)
            if action.target and fnmatch.fnmatch(action.target, self.target_pattern):
                return True
            # Match 2: SHELL_EXECUTE also checks details[cmd] for the command string
            if action.action_type == ActionType.SHELL_EXECUTE:
                cmd = action.details.get("cmd", "") if action.details else ""
                if cmd and fnmatch.fnmatch(cmd, self.target_pattern):
                    return True
            # Match 3: pattern is checked against target and (for shell) cmd
            # pattern targets paths like "/*" or "/home*", not command prefixes
            # If neither field matched, the rule does not apply
            return False
        return True


class SafetyEngine:
    """
    核心安全引擎。

    用法（同步模式）：
        engine = SafetyEngine()
        decision = engine.evaluate(action)
        if decision.decision == "BLOCK":
            print("已拦截")

    用法（中间件模式）：
        async def my_middleware(next_fn, action):
            decision = engine.evaluate(action)
            if decision.decision == "BLOCK":
                raise PermissionError("Action blocked")
            return await next_fn(action)
        engine.add_middleware(my_middleware)
    """

    def __init__(
        self,
        rules: list[PolicyRule] | None = None,
        llm_judge: Callable[[SafetyAction], Awaitable[str] | str] | None = None,
        circuit_breaker_threshold: int = 5,      # 5次 HIGH+ 触发熔断
        circuit_breaker_window: int = 60,        # 60秒窗口
    ):
        from .policies import default_policies
        self._rules = rules or [PolicyRule(**p) for p in default_policies]
        self._llm_judge = llm_judge
        self._middlewares: list[Callable] = []

        # 熔断器状态
        self._cb_threshold = circuit_breaker_threshold
        self._cb_window = circuit_breaker_window
        self._cb_events: list[float] = []  # 时间戳列表
        self._cb_open = False
        self._cb_opened_at: float | None = None

    def add_middleware(self, fn: Callable):
        """注册中间件，先进后出（outer→inner）"""
        self._middlewares.append(fn)

    def _check_circuit_breaker(self) -> bool:
        """检查是否触发熔断"""
        now = time.time()
        # 移除窗口外的事件
        self._cb_events = [t for t in self._cb_events if now - t < self._cb_window]
        if len(self._cb_events) >= self._cb_threshold:
            self._cb_open = True
            self._cb_opened_at = now
            return True
        return False

    def _record_risk_event(self):
        """记录一次高风险事件"""
        self._cb_events.append(time.time())

    def evaluate(self, action: SafetyAction) -> SafetyDecision:
        """
        评估单个 Action，返回 SafetyDecision。

        评估顺序：
        1. 熔断器检查
        2. 规则匹配（按优先级）
        3. LLM 辅助（可选）
        """
        # 1. 熔断检查
        if self._cb_open:
            # 检查是否自动恢复（熔断打开30秒后）
            if self._cb_opened_at and (time.time() - self._cb_opened_at) > 30:
                self._cb_open = False
                self._cb_events.clear()
            else:
                return SafetyDecision(
                    action_id=action.action_id,
                    risk_level=RiskLevel.CRITICAL,
                    decision="CIRCUIT_BREAK",
                    reason="熔断器已触发，高风险操作暂停",
                    risk_score=1.0,
                )

        # 2. 规则匹配
        base_score = action.risk_score
        matched_rules: list[str] = []
        override_decision: str | None = None
        override_reason: str | None = None
        override_level: RiskLevel | None = None

        for rule in self._rules:
            if rule.matches(action):
                matched_rules.append(rule.rule_id)
                if rule.decision in ("BLOCK", "WARN"):
                    # 取最高风险
                    if override_level is None or rule.risk_level.value > override_level.value:
                        override_level = rule.risk_level
                    if override_decision is None:
                        override_decision = rule.decision
                        override_reason = rule.reason

        # 3. 计算最终决策
        if override_decision:
            risk_level = override_level or RiskLevel.HIGH
            final_decision = override_decision
            reason = override_reason or ""
        else:
            # 基于评分决策
            if base_score >= 0.8:
                risk_level = RiskLevel.HIGH
                final_decision = "WARN" if not action.dry_run else "ALLOW"
                reason = f"高风险操作（评分 {base_score:.2f}），建议人工确认"
            elif base_score >= 0.5:
                risk_level = RiskLevel.MEDIUM
                final_decision = "ALLOW"
                reason = f"中等风险，记录日志"
            else:
                risk_level = RiskLevel.LOW
                final_decision = "ALLOW"
                reason = "低风险操作，直接放行"

        # CRITICAL 操作自动 BLOCK（非 dry_run）
        if risk_level == RiskLevel.CRITICAL and not action.dry_run:
            final_decision = "BLOCK"
            reason = "关键风险操作，自动拦截"

        # 记录高风险事件
        if risk_level.value >= RiskLevel.HIGH.value:
            self._record_risk_event()
            if self._check_circuit_breaker():
                final_decision = "CIRCUIT_BREAK"
                reason += "（熔断器已触发）"

        return SafetyDecision(
            action_id=action.action_id,
            risk_level=risk_level,
            decision=final_decision,
            reason=reason,
            risk_score=base_score,
            matched_policies=matched_rules,
            timestamp=time.time(),
        )

    async def evaluate_async(self, action: SafetyAction) -> SafetyDecision:
        """异步评估（支持 LLM 辅助）"""
        decision = self.evaluate(action)

        # LLM 辅助判断
        if self._llm_judge and decision.decision == "WARN":
            try:
                advice = self._llm_judge(action)
                if callable(advice):
                    advice = await advice(action)
                if advice:
                    decision.llm_advice = advice
                    # 如果 LLM 说危险，提升到 BLOCK
                    if any(kw in advice.lower() for kw in ["危险", "block", "critical", "拒绝"]):
                        decision.decision = "BLOCK"
                        decision.risk_level = RiskLevel.CRITICAL
            except Exception as e:
                logger.warning(f"LLM judge failed: {e}")

        return decision

    def add_rule(self, rule: PolicyRule):
        """动态添加规则"""
        self._rules.append(rule)

    def remove_rule(self, rule_id: str):
        """动态移除规则"""
        self._rules = [r for r in self._rules if r.rule_id != rule_id]

    def get_stats(self) -> dict:
        """获取安全统计"""
        return {
            "total_rules": len(self._rules),
            "circuit_breaker_open": self._cb_open,
            "risk_events_in_window": len(self._cb_events),
            "middlewares_count": len(self._middlewares),
        }

    def reset_circuit_breaker(self) -> dict:
        """公开重置熔断器 (V 6/13 22:14 加, SOP #23 5 大发现 #4).

        设计: 原本 _cb_open / _cb_events 是私有, 调用方需直接设置属性
        (symphony 等需要程序化 reset). 加公开方法, 返 reset 后状态.

        Returns:
            dict with reset 前后状态, 供调用方 verify.
        """
        before = {
            "circuit_breaker_open": self._cb_open,
            "risk_events_in_window": len(self._cb_events),
        }
        self._cb_open = False
        self._cb_events = []
        self._cb_opened_at = None
        return {
            "reset": True,
            "before": before,
            "after": {
                "circuit_breaker_open": self._cb_open,
                "risk_events_in_window": len(self._cb_events),
            },
        }
