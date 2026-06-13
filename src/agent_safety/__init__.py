"""AgentSafety - 交响乐技能家族 · Agent 行为安全监控系统"""

from __future__ import annotations

# 核心引擎（独立使用，不依赖 skill 接口）
from .core import SafetyEngine, SafetyAction, SafetyDecision, PolicyRule, ActionType, RiskLevel
from .policies import PolicyStore, default_policies

# Skill 接口（CircuitBreaker/CircuitState/PermissionScope 在 skill.py 中）
from .skill import SafetySkill, CircuitBreaker, CircuitState, PermissionScope, PermissionChecker
from ._skill_base import SkillBase

__version__ = "1.0.0"
__all__ = [
    "SafetyEngine",
    "SafetyAction",
    "SafetyDecision",
    "PolicyRule",
    "ActionType",
    "RiskLevel",
    "PolicyStore",
    "default_policies",
    "SafetySkill",
    "SkillBase",
    "CircuitBreaker",
    "CircuitState",
    "PermissionScope",
    "PermissionChecker",
]
