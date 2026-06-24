"""
AgentSafety Core - 核心风险评估引擎
"""

from __future__ import annotations

import time
import logging
import math
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Callable, Awaitable
from collections import defaultdict

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# 格雷厄姆安全边际 + 西蒙斯噪声模式 + 琼斯非对称风险
# 三位一体风险管理框架
# ══════════════════════════════════════════════════════════════════════════════


class MarginCalculator:
    """
    格雷厄姆安全边际计算机。
    
    核心问题不是"能涨多少"而是"跌多少能接受"。
    安全边际 = 保护区间，误报成本 vs 漏报成本的量化权衡。
    
    公式:
      margin = (break_score - current_score) / break_score
      expected_cost = P(false_positive) * cost_fp + P(false_negative) * cost_fn
      decision = ALLOW if margin > threshold else WARN/BLOCK
    
    阈值设置原则:
      - BLOCK 阈值: margin > 0.3 (30% 安全边际)
      - WARN 阈值: margin > 0.15 (15% 安全边际)
      - 未知类型操作: 最低 margin 0.4 (更保守)
    """

    # 漏报成本系数 (未知威胁的潜在损失)
    COST_FN = 10.0   # 漏报惩罚系数
    # 误报成本系数 (对生产力的影响)
    COST_FP = 1.0    # 误报惩罚系数

    def __init__(
        self,
        block_margin: float = 0.30,
        warn_margin: float = 0.15,
        unknown_margin: float = 0.40,
        cost_fn: float = 10.0,
        cost_fp: float = 1.0,
    ):
        self._block_margin = block_margin
        self._warn_margin = warn_margin
        self._unknown_margin = unknown_margin
        self.COST_FN = cost_fn
        self.COST_FP = cost_fp

    def compute_margin(self, score: float, is_known_pattern: bool = True) -> float:
        """
        计算安全边际。
        
        Args:
            score: 当前风险评分 0.0-1.0
            is_known_pattern: 是否为已知攻击模式（规则匹配）
                              已知模式允许更小边际（确定性高）
                              未知模式需要更大边际（不确定性高）
        """
        # break_score 是决策阈值
        if not is_known_pattern:
            # 未知模式：需要更大的安全边际
            break_score = 1.0 - self._unknown_margin
        else:
            # 已知模式：用 block_margin 推导 break_score
            break_score = 1.0 - self._block_margin

        if score >= break_score:
            return 0.0  # 已经突破安全边际

        # 安全边际 = 保护区间 / 总区间
        margin = (break_score - score) / break_score
        return max(0.0, margin)

    def decision_with_margin(
        self,
        score: float,
        is_known_pattern: bool = True,
        dry_run: bool = False,
    ) -> tuple[str, RiskLevel, float]:
        """
        基于安全边际的决策。
        
        Returns:
            (decision, risk_level, margin)
        """
        margin = self.compute_margin(score, is_known_pattern)

        # 未知操作 + dry_run: 保守策略
        if not is_known_pattern and dry_run:
            return "WARN", RiskLevel.HIGH, margin

        # 基于边际决策
        if margin >= self._block_margin:
            # 充足安全边际：放行
            return "ALLOW", RiskLevel.LOW, margin
        elif margin >= self._warn_margin:
            # 中等边际：警告
            return "WARN", RiskLevel.MEDIUM, margin
        else:
            # 边际不足：阻止（已知模式）或阻止（未知模式高分）
            return "BLOCK", RiskLevel.HIGH, margin

    def expected_cost(self, score: float, is_known: bool) -> float:
        """
        计算期望损失（格雷厄姆核心）：
        
        E[loss] = P(FP) * Cost(FP) + P(FN) * Cost(FN)
        
        其中:
          P(FP) = 当 score 低时错误阻止的概率
          P(FN) = 当 score 高时错误放行的概率
        """
        # P(FN) 随 score 增加而增加（高分=更可能危险）
        p_fn = score ** 2
        
        # P(FP) 随 score 增加而减少（低分=更可能是误报）
        p_fp = (1 - score) ** 2
        
        # 未知模式的不确定性惩罚
        uncertainty = 1.5 if not is_known else 1.0
        
        expected = (p_fp * self.COST_FP + p_fn * self.COST_FN) * uncertainty
        return expected

    def get_defensive_bias(self) -> str:
        """
        返回当前配置的防御倾向。
        格雷厄姆: 先考虑不亏钱，再考虑赚钱。
        """
        return (
            f"defensive"
            if self.COST_FN > self.COST_FP * 3
            else "balanced"
            if self.COST_FN > self.COST_FP
            else "offensive"
        )


class SignalNoiseSeparator:
    """
    西蒙斯噪声模式分离器。
    
    Medallion Fund 成功秘诀：区分噪声和信号。
    不是所有模式都是真实的——很多是随机波动。
    
    核心概念:
      SNR = |signal_mean| / noise_std
      signal_confidence = 1 - P(noise)
    
    DreamNet 洞见质量评估:
      - 真信号: 高频重复 + 跨来源验证 + 因果机制
      - 噪声: 偶发 + 单来源 + 表面相关
    """

    # 噪声检测阈值
    MIN_SIGNAL_FREQ = 2       # 最小信号频率
    NOISE_PROB_THRESHOLD = 0.35  # 噪声概率阈值

    def __init__(
        self,
        min_signal_freq: int = 2,
        noise_prob_threshold: float = 0.35,
    ):
        self._min_signal_freq = min_signal_freq
        self._noise_prob_threshold = noise_prob_threshold
        self._signal_history: dict[str, list[float]] = defaultdict(list)

    def assess_snr(
        self,
        item_id: str,
        observations: list[float],
        cross_source_count: int = 1,
    ) -> dict:
        """
        评估信号/噪声比。
        
        Args:
            item_id: 条目标识
            observations: 多次观测值列表
            cross_source_count: 跨来源验证数量（>1表示信号更强）
        
        Returns:
            dict with snr, signal_prob, noise_prob, confidence
        """
        if not observations:
            return {
                "snr": 0.0,
                "signal_prob": 0.0,
                "noise_prob": 1.0,
                "confidence": 0.0,
                "is_signal": False,
            }

        # 基础统计
        n = len(observations)
        mean_val = sum(observations) / n
        
        # 方差（噪声水平）
        variance = sum((x - mean_val) ** 2 for x in observations) / max(n - 1, 1)
        noise_std = math.sqrt(variance) if variance > 0 else 0.001

        # SNR: 信号强度 / 噪声水平
        snr = abs(mean_val) / noise_std if noise_std > 0 else 0.0

        # 信号频率权重
        freq_weight = min(n / self._min_signal_freq, 1.0)

        # 跨来源验证权重（越多来源=信号越真实）
        source_weight = min(cross_source_count / 3.0, 1.0)

        # 综合信号概率
        signal_prob = min(1.0, snr * 0.3 + freq_weight * 0.4 + source_weight * 0.3)

        # 噪声概率
        noise_prob = 1.0 - signal_prob

        # 置信度（综合）
        confidence = signal_prob * freq_weight

        is_signal = (
            n >= self._min_signal_freq
            and signal_prob > self._noise_prob_threshold
            and cross_source_count >= 1
        )

        result = {
            "snr": round(snr, 3),
            "signal_prob": round(signal_prob, 3),
            "noise_prob": round(noise_prob, 3),
            "confidence": round(confidence, 3),
            "is_signal": is_signal,
            "observation_count": n,
            "cross_source_count": cross_source_count,
            "mean": round(mean_val, 3),
            "noise_std": round(noise_std, 3),
        }

        self._signal_history[item_id] = observations[-20:]  # 保留最近20条
        return result

    def filter_noise(self, insights: list) -> tuple[list, list]:
        """
        过滤 DreamNet 洞见中的噪声。
        
        Returns:
            (signals, noise) - 信号洞见和噪声洞见
        """
        signals = []
        noise = []

        for insight in insights:
            # 重建观测序列（从质量分数）
            obs = [insight.get("quality", 0.5)] * 3
            
            # 跨来源数（从 heterodox 标记推断）
            cross_source = 2 if insight.get("is_heterodox") else 1

            assessment = self.assess_snr(
                insight.get("id", ""),
                obs,
                cross_source,
            )

            if assessment["is_signal"]:
                insight["_snr_assessment"] = assessment
                signals.append(insight)
            else:
                insight["_snr_assessment"] = assessment
                noise.append(insight)

        return signals, noise

    def get_signal_stats(self) -> dict:
        """获取信号分离统计"""
        total = sum(len(v) for v in self._signal_history.values())
        return {
            "unique_signals": len(self._signal_history),
            "total_observations": total,
            "min_signal_freq": self._min_signal_freq,
            "noise_prob_threshold": self._noise_prob_threshold,
        }


class AsymmetricRiskManager:
    """
    保罗·都铎·琼斯非对称风险管理器。
    
    核心理念: 不预测方向，而是管理风险敞口。
    
    关键洞察:
      - 未知威胁的损失 >> 误报的损失
      - 因此: P(unknown_threat) * Loss(unknown) >> P(false_alarm) * Loss(false_alarm)
      - 对未知威胁应该有非对称保护（过保护）
    
    实现:
      - 未知操作类型自动提升风险等级
      - 高方差/低置信度决策触发额外保护
      - 累积不确定性超阈值时触发 circuit breaker
    """

    # 非对称风险系数：未知威胁的额外惩罚
    UNKNOWN_THREAT_PENALTY = 2.5    # 未知威胁风险倍数
    UNCERTAINTY_CB_THRESHOLD = 0.7  # 不确定性熔断阈值
    LOW_CONFIDENCE_THRESHOLD = 0.4  # 低置信度阈值

    def __init__(
        self,
        unknown_threat_penalty: float = 2.5,
        uncertainty_cb_threshold: float = 0.7,
        low_confidence_threshold: float = 0.4,
    ):
        self._unknown_threat_penalty = unknown_threat_penalty
        self._uncertainty_cb_threshold = uncertainty_cb_threshold
        self._low_confidence_threshold = low_confidence_threshold
        self._uncertainty_history: list[float] = []

    def compute_asymmetric_score(
        self,
        base_score: float,
        is_known_threat: bool,
        pattern_confidence: float = 1.0,
        decision_history_variance: float = 0.0,
    ) -> float:
        """
        计算非对称风险评分。
        
        Args:
            base_score: 基础风险评分
            is_known_threat: 是否为已知威胁
            pattern_confidence: 模式匹配置信度 (0-1)
            decision_history_variance: 决策历史方差（高方差=不确定）
        
        Returns:
            非对称调整后的风险评分
        """
        # 已知威胁：直接使用基础评分
        if is_known_threat:
            adjusted = base_score
        else:
            # 未知威胁：应用非对称惩罚
            adjusted = min(1.0, base_score * self._unknown_threat_penalty)

        # 模式置信度惩罚（低置信度=更多不确定性）
        confidence_penalty = (1.0 - pattern_confidence) * 0.2
        adjusted = min(1.0, adjusted + confidence_penalty)

        # 决策历史方差惩罚（高方差=系统不确定）
        variance_penalty = decision_history_variance * 0.15
        adjusted = min(1.0, adjusted + variance_penalty)

        return adjusted

    def should_circuit_break_on_uncertainty(self) -> bool:
        """
        检查是否应该因不确定性而触发熔断。
        
        逻辑：连续低置信度决策累积 = 系统对威胁无能为力 = 熔断
        """
        if len(self._uncertainty_history) < 5:
            return False

        # 计算最近不确定性的滑动均值
        recent = self._uncertainty_history[-10:]
        avg_uncertainty = sum(recent) / len(recent)

        # 记录并清理
        if len(self._uncertainty_history) > 50:
            self._uncertainty_history = self._uncertainty_history[-50:]

        return avg_uncertainty > self._uncertainty_cb_threshold

    def record_decision_confidence(self, confidence: float):
        """记录决策置信度（用于不确定性追踪）"""
        self._uncertainty_history.append(confidence)

    def get_asymmetric_protection_level(
        self,
        is_known_threat: bool,
        pattern_confidence: float,
    ) -> str:
        """
        获取非对称保护级别。
        
        Returns:
            "full" - 完全保护（BLOCK）
            "strong" - 强保护（WARN + 额外日志）
            "normal" - 正常保护
        """
        if not is_known_threat:
            if pattern_confidence < self._low_confidence_threshold:
                return "full"
            return "strong"
        return "normal"

    def get_protection_report(self) -> dict:
        """获取当前保护状态报告"""
        recent = self._uncertainty_history[-20:] if self._uncertainty_history else [0.0]
        avg = sum(recent) / len(recent)
        return {
            "unknown_threat_penalty": self._unknown_threat_penalty,
            "uncertainty_cb_threshold": self._uncertainty_cb_threshold,
            "current_avg_uncertainty": round(avg, 3),
            "should_cb_on_uncertainty": self.should_circuit_break_on_uncertainty(),
            "decisions_recorded": len(self._uncertainty_history),
            "protection_bias": "asymmetric_defensive",
        }


class RiskLevel(Enum):
    """风险等级：CRITICAL > HIGH > MEDIUM > LOW > NONE"""
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self):
        return self.name


# ══════════════════════════════════════════════════════════════════════════════
# Alperovitch 网络地缘政治：威胁来源与动机追踪
# 攻击者的来源和动机决定防御策略——不只是攻击类型
# ══════════════════════════════════════════════════════════════════════════════


class ThreatSource(Enum):
    """
    威胁来源分类（Alperovitch 网络地缘政治框架）。
    
    不同于传统安全只关注"是什么攻击"，我们追问"是谁在攻击"和"为什么"。
    不同来源的威胁有不同的：意图、手段、容忍度。
    """
    UNKNOWN = "unknown"           # 未知来源
    INTERNAL = "internal"        # 内部误操作/恶意内部人员
    STATE_ACTOR = "state_actor"  # 国家级攻击者（APT）
    CRIME_ORG = "crime_org"       # 有组织犯罪
    HACKTIVIST = "hacktivist"    # 黑客行动主义
    SCRIPT_KIDDIE = "script_kiddie"  # 脚本小子
    SUPPLY_CHAIN = "supply_chain"  # 供应链攻击


class ThreatMotivation(Enum):
    """
    威胁动机分类。同一攻击类型，不同动机 = 不同防御策略。
    """
    ESPIONAGE = "espionage"       # 间谍活动（窃取数据）
    SABOTAGE = "sabotage"         # 破坏（致瘫系统）
    FINANCIAL = "financial"       # 财务利益
    IDEOLOGICAL = "ideological"   # 意识形态
    NATIONALLY_STRATEGIC = "nationally_strategic"  # 国家战略（华为级别）
    UNKNOWN = "unknown"


class ThreatAttribution:
    """
    威胁归因数据（Alperovitch 框架）。
    
    问题："AgentSafety 是否考虑了威胁来源和动机？还是只关注攻击类型？"
    答案：之前只关注类型，现在加入来源/动机维度。
    
    防御策略变化：
    - 内部威胁 → 重点监控数据出口
    - 国家级APT → 假设已渗透，深度监测
    - 供应链攻击 → 验证所有依赖的完整性
    """
    
    def __init__(
        self,
        source: ThreatSource = ThreatSource.UNKNOWN,
        motivation: ThreatMotivation = ThreatMotivation.UNKNOWN,
        country_code: str = None,       # ISO 3166-1 alpha-2
        actor_name: str = None,          # 已知攻击组织名
        confidence: float = 0.0,         # 归因置信度 0-1
        is_supply_chain: bool = False,   # 是否为供应链攻击
        ttps: list[str] = None,          # MITRE ATT&CK tactics/techniques
    ):
        self.source = source
        self.motivation = motivation
        self.country_code = country_code
        self.actor_name = actor_name
        self.confidence = confidence
        self.is_supply_chain = is_supply_chain
        self.ttps = ttps or []
    
    def is_state_sponsored(self) -> bool:
        """是否为国家行为体"""
        return self.source == ThreatSource.STATE_ACTOR
    
    def is_critical_infrastructure_target(self) -> bool:
        """是否在攻击关键基础设施"""
        return self.motivation in (
            ThreatMotivation.NATIONALLY_STRATEGIC,
            ThreatMotivation.SABOTAGE,
        )
    
    def requires_supply_chain_defense(self) -> bool:
        """是否需要供应链防御模式"""
        return self.is_supply_chain or self.source == ThreatSource.SUPPLY_CHAIN
    
    def to_dict(self) -> dict:
        return {
            "source": self.source.value,
            "motivation": self.motivation.value,
            "country_code": self.country_code,
            "actor_name": self.actor_name,
            "confidence": self.confidence,
            "is_supply_chain": self.is_supply_chain,
            "ttps": self.ttps,
        }


# ══════════════════════════════════════════════════════════════════════════════
# 任正非 灰度理论：超越 BLOCK/WARN 的灰度决策
# 管理者核心能力：在黑白之间做决策
# 问题："AgentSafety 的 BLOCK/WARN 决策是否过于二元化？"
# 答案：需要灰度决策机制—— graduated response
# ══════════════════════════════════════════════════════════════════════════════


class GraduatedDecision(Enum):
    """
    灰度决策层级（任正非灰度理论）。
    
    不是简单的 ALLOW/BLOCK，而是在连续光谱上选择位置：
    - FULL_ALLOW: 完全放行
    - READ_ONLY: 只读模式（降级）
    - SANDBOX: 沙箱执行
    - RATE_LIMITED: 限流观察
    - WARN: 警告+人工确认
    - BLOCK: 阻止
    - CIRCUIT_BREAK: 熔断（极限生存）
    """
    FULL_ALLOW = "full_allow"         # 完全放行
    READ_ONLY = "read_only"           # 只读降级（高风险写操作降级为读）
    SANDBOX = "sandbox"               # 沙箱执行（隔离环境）
    RATE_LIMITED = "rate_limited"     # 限流（高风险操作限制频率）
    WARN = "warn"                    # 警告（需要人工确认）
    BLOCK = "block"                   # 阻止
    CIRCUIT_BREAK = "circuit_break"  # 熔断（极端情况，任正非"极限生存"）
    
    # 决策强度（类常量）
    SEVERITY_ORDER = [
        "full_allow",
        "rate_limited",
        "read_only",
        "sandbox",
        "warn",
        "block",
        "circuit_break",
    ]

    @property
    def _severity_index(self) -> int:
        return self.SEVERITY_ORDER.index(self.value)
    
    def __ge__(self, other: "GraduatedDecision") -> bool:
        return self._severity_index >= other._severity_index
    
    def __gt__(self, other: "GraduatedDecision") -> bool:
        return self._severity_index > other._severity_index
    
    def __le__(self, other: "GraduatedDecision") -> bool:
        return self._severity_index <= other._severity_index
    
    def __lt__(self, other: "GraduatedDecision") -> bool:
        return self._severity_index < other._severity_index


class GrayScaleDecisionEngine:
    """
    灰度决策引擎（任正非灰度理论实现）。
    
    核心理念：在黑白之间找到最优位置。
    不是"拦不拦"，而是"怎么拦"——降级、限流、沙箱，都是"拦"的方式。
    
    灰度因素：
    1. 风险评分（连续值）
    2. 威胁来源（国家 vs 脚本小子）
    3. 操作类型（破坏性 vs 只读性）
    4. 上下文（干运行 vs 生产）
    5. 历史行为（首次 vs 惯犯）
    """
    
    def __init__(
        self,
        # 风险阈值
        full_allow_threshold: float = 0.2,
        rate_limit_threshold: float = 0.4,
        read_only_threshold: float = 0.55,
        sandbox_threshold: float = 0.7,
        warn_threshold: float = 0.8,
        block_threshold: float = 0.9,
    ):
        self._thresholds = {
            GraduatedDecision.FULL_ALLOW: full_allow_threshold,
            GraduatedDecision.RATE_LIMITED: rate_limit_threshold,
            GraduatedDecision.READ_ONLY: read_only_threshold,
            GraduatedDecision.SANDBOX: sandbox_threshold,
            GraduatedDecision.WARN: warn_threshold,
            GraduatedDecision.BLOCK: block_threshold,
            # CIRCUIT_BREAK 由熔断器专门处理
        }
    
    def decide(
        self,
        risk_score: float,
        threat_attribution: ThreatAttribution = None,
        is_dry_run: bool = True,
        action_is_destructive: bool = False,
        repeated_offense_count: int = 0,
    ) -> tuple[GraduatedDecision, str]:
        """
        灰度决策。
        
        Args:
            risk_score: 0-1 风险评分
            threat_attribution: 威胁归因（Alperovitch）
            is_dry_run: 是否试运行
            action_is_destructive: 操作是否具有破坏性
            repeated_offense_count: 重复违规次数
        
        Returns:
            (GraduatedDecision, reason)
        """
        # 干运行模式：默认更保守
        if is_dry_run and risk_score < 0.6:
            return GraduatedDecision.FULL_ALLOW, "试运行模式，低风险"
        
        # 破坏性操作自动升级
        if action_is_destructive:
            risk_score = min(1.0, risk_score * 1.3)
        
        # 重复违规：升级防御
        if repeated_offense_count > 0:
            escalation = min(repeated_offense_count * 0.1, 0.3)
            risk_score = min(1.0, risk_score + escalation)
        
        # 国家级威胁：最高防御级别（Alperovitch）
        if threat_attribution and threat_attribution.is_state_sponsored():
            # 假设已渗透，强制沙箱或更高
            if risk_score > 0.3:
                return (
                    GraduatedDecision.SANDBOX,
                    f"国家行为体威胁({threat_attribution.actor_name or 'APT'})，强制沙箱"
                )
        
        # 关键基础设施目标：不允许破坏
        if threat_attribution and threat_attribution.is_critical_infrastructure_target():
            if action_is_destructive:
                return (
                    GraduatedDecision.BLOCK,
                    "关键基础设施，禁止破坏性操作"
                )
        
        # 供应链攻击：假设依赖不可信
        if threat_attribution and threat_attribution.requires_supply_chain_defense():
            risk_score = min(1.0, risk_score * 1.2)
        
        # 基于风险评分选择灰度决策
        decision = GraduatedDecision.FULL_ALLOW
        # 按严重度从高到低遍历（排除最后的 circuit_break）
        for level in list(GraduatedDecision)[5::-1]:  # BLOCK到FULL_ALLOW
            if risk_score >= self._thresholds.get(level, 1.0):
                decision = level
                break
        
        reasons = {
            GraduatedDecision.FULL_ALLOW: f"风险评分{risk_score:.2f}低于阈值，放行",
            GraduatedDecision.RATE_LIMITED: f"风险评分{risk_score:.2f}中等，限流观察",
            GraduatedDecision.READ_ONLY: f"风险评分{risk_score:.2f}较高，降级为只读",
            GraduatedDecision.SANDBOX: f"风险评分{risk_score:.2f}高，强制沙箱执行",
            GraduatedDecision.WARN: f"风险评分{risk_score:.2f}很高，需人工确认",
            GraduatedDecision.BLOCK: f"风险评分{risk_score:.2f}极高，阻止操作",
        }
        
        return decision, reasons.get(decision, "灰度决策")


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
    """
    被监控的 Action
    
    扩展字段（Alperovitch 威胁来源追踪）：
    - source_ip: 请求来源 IP，用于威胁归因
    - threat_attribution: 威胁归因数据（来源/动机/置信度）
    """
    action_id: str                    # 唯一标识
    action_type: ActionType           # Action 类型
    agent_id: str                     # 发起者 Agent ID
    timestamp: float = field(default_factory=time.time)
    details: dict = field(default_factory=dict)  # 原始参数
    tool_name: Optional[str] = None   # 调用的工具名
    target: Optional[str] = None      # 操作目标（文件路径/URL等）
    dry_run: bool = False             # 是否为试运行
    # ── Alperovitch 威胁来源追踪 ────────────────────────────
    source_ip: Optional[str] = None   # 请求来源 IP（用于归因）
    threat_attribution: Optional[ThreatAttribution] = None  # 威胁归因

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

    @property
    def is_destructive(self) -> bool:
        """是否为破坏性操作"""
        return self.action_type in (
            ActionType.FILE_DELETE,
            ActionType.DATA_DELETE,
        )


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


class CircuitBreakerState(Enum):
    """熔断器状态"""
    CLOSED = "closed"      # 正常关闭，允许请求通过
    OPEN = "open"          # 打开，拒绝所有请求
    HALF_OPEN = "half_open"  # 半开，允许部分请求通过


class CircuitBreaker:
    """
    独立熔断器类（从 SafetyEngine 解耦）。

    状态转换：
    - CLOSED → OPEN：失败次数达到阈值
    - OPEN → HALF_OPEN：熔断超时后
    - HALF_OPEN → CLOSED：Probe 成功
    - HALF_OPEN → OPEN：Probe 失败

    用法：
        cb = CircuitBreaker(failure_threshold=5, recovery_timeout=30, half_open_max_calls=3)
        result = cb.call(some_function, *args, **kwargs)
        cb.record_success()
        cb.record_failure()
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        half_open_max_calls: int = 3,
        name: str = "default",
    ):
        self._state = CircuitBreakerState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: float | None = None
        self._failure_threshold = failure_threshold
        self._recovery_timeout = recovery_timeout
        self._half_open_max_calls = half_open_max_calls
        self._half_open_calls = 0
        self._name = name
        self._total_opens = 0

    def call(self, func: Callable, *args, **kwargs):
        """执行函数，熔断开启时直接拒绝"""
        if self._state == CircuitBreakerState.OPEN:
            # 检查是否超时恢复
            if self._last_failure_time and (time.time() - self._last_failure_time) >= self._recovery_timeout:
                self._transition_to_half_open()
            else:
                raise CircuitBreakerOpen(f"Circuit breaker '{self._name}' is OPEN")

        if self._state == CircuitBreakerState.HALF_OPEN:
            if self._half_open_calls >= self._half_open_max_calls:
                raise CircuitBreakerOpen(f"Circuit breaker '{self._name}' is HALF_OPEN, max calls reached")

        # 执行调用
        try:
            result = func(*args, **kwargs)
            self.record_success()
            return result
        except Exception as e:
            self.record_failure()
            raise

    def record_success(self):
        """记录成功调用"""
        if self._state == CircuitBreakerState.HALF_OPEN:
            self._success_count += 1
            if self._success_count >= self._half_open_max_calls:
                self._transition_to_closed()
        elif self._state == CircuitBreakerState.CLOSED:
            self._failure_count = 0  # 重置失败计数

    def record_failure(self):
        """记录失败调用"""
        self._failure_count += 1
        self._last_failure_time = time.time()

        if self._state == CircuitBreakerState.HALF_OPEN:
            self._transition_to_open()
        elif self._state == CircuitBreakerState.CLOSED:
            if self._failure_count >= self._failure_threshold:
                self._transition_to_open()

    def get_state(self) -> CircuitBreakerState:
        """获取当前状态"""
        # OPEN 状态下检查超时
        if self._state == CircuitBreakerState.OPEN:
            if self._last_failure_time and (time.time() - self._last_failure_time) >= self._recovery_timeout:
                self._transition_to_half_open()
        return self._state

    def _transition_to_open(self):
        self._state = CircuitBreakerState.OPEN
        self._total_opens += 1
        logger.warning(f"Circuit breaker '{self._name}' transitioned to OPEN")

    def _transition_to_half_open(self):
        self._state = CircuitBreakerState.HALF_OPEN
        self._half_open_calls = 0
        self._success_count = 0
        logger.info(f"Circuit breaker '{self._name}' transitioned to HALF_OPEN")

    def _transition_to_closed(self):
        self._state = CircuitBreakerState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._half_open_calls = 0
        logger.info(f"Circuit breaker '{self._name}' transitioned to CLOSED")

    def reset(self):
        """手动重置熔断器"""
        self._transition_to_closed()

    def get_stats(self) -> dict:
        """获取熔断器统计"""
        return {
            "name": self._name,
            "state": self.get_state().value,
            "failure_count": self._failure_count,
            "total_opens": self._total_opens,
            "failure_threshold": self._failure_threshold,
            "recovery_timeout": self._recovery_timeout,
        }


class CircuitBreakerOpen(Exception):
    """熔断器开启异常"""
    pass


class PolicyLearner:
    """
    策略学习器 - 分析事件并生成规则建议。

    用法：
        learner = PolicyLearner()
        analysis = learner.analyze_recent_events(events)
        suggestions = learner.suggest_rules(events)
        learner.adapt_threshold("SHELL_EXECUTE", 0.7)
    """

    def __init__(self, min_confidence: float = 0.8):
        self._min_confidence = min_confidence
        self._threshold_overrides: dict[str, float] = {}
        self._learned_patterns: dict[str, int] = defaultdict(int)
        self._event_count: dict[str, int] = defaultdict(int)

    def analyze_recent_events(self, events: list, window_hours: int = 24) -> dict:
        """
        分析近期事件，返回统计摘要。

        Args:
            events: SafetyAction 或 SafetyDecision 列表
            window_hours: 分析窗口小时数

        Returns:
            dict with analysis results
        """
        now = time.time()
        window_seconds = window_hours * 3600
        recent_events = [e for e in events if (now - getattr(e, 'timestamp', 0)) <= window_seconds]

        if not recent_events:
            return {
                "total_events": 0,
                "event_types": {},
                "risk_distribution": {},
                "top_targets": [],
                "time_window_hours": window_hours,
            }

        # 按类型统计
        event_types: dict[str, int] = defaultdict(int)
        risk_levels: dict[str, int] = defaultdict(int)
        targets: dict[str, int] = defaultdict(int)

        for event in recent_events:
            action_type = getattr(event, 'action_type', None)
            if action_type:
                event_types[action_type.value if hasattr(action_type, 'value') else str(action_type)] += 1

            risk_level = getattr(event, 'risk_level', None)
            if risk_level:
                risk_levels[risk_level.name if hasattr(risk_level, 'name') else str(risk_level)] += 1

            target = getattr(event, 'target', None)
            if target:
                targets[target] += 1

        # 记录学习数据
        for event in recent_events:
            key = f"{getattr(event, 'action_type', 'unknown')}:{getattr(event, 'target', '')}"
            self._event_count[key] += 1

        return {
            "total_events": len(recent_events),
            "event_types": dict(event_types),
            "risk_distribution": dict(risk_levels),
            "top_targets": sorted(targets.items(), key=lambda x: -x[1])[:10],
            "time_window_hours": window_hours,
            "blocked_count": sum(1 for e in recent_events if getattr(e, 'decision', None) == "BLOCK"),
            "warn_count": sum(1 for e in recent_events if getattr(e, 'decision', None) == "WARN"),
        }

    def suggest_rules(self, events: list) -> list[dict]:
        """
        基于历史事件生成新规则建议。

        Returns:
            list of rule suggestion dicts
        """
        if len(events) < 10:
            return []

        suggestions = []
        analysis = self.analyze_recent_events(events)

        # 分析高风险目标模式
        for target, count in analysis.get("top_targets", []):
            if count >= 5:
                suggestions.append({
                    "rule_id": f"auto_generated_{target[:20]}",
                    "name": f"自动规则: {target[:30]}",
                    "action_type": None,
                    "target_pattern": target,
                    "risk_level": "HIGH",
                    "decision": "WARN",
                    "reason": f"近期检测到 {count} 次相关操作，建议监控",
                    "auto_generated": True,
                    "confidence": min(count / 50.0, 0.95),
                })

        # 分析危险操作类型
        high_risk_types = [k for k, v in analysis.get("event_types", {}).items() if v >= 10]
        for action_type in high_risk_types:
            suggestions.append({
                "rule_id": f"auto_{action_type}",
                "name": f"高频操作监控: {action_type}",
                "action_type": action_type,
                "target_pattern": None,
                "risk_level": "MEDIUM",
                "decision": "ALLOW",
                "reason": f"高频操作类型 {action_type}，建议记录日志",
                "auto_generated": True,
                "confidence": 0.7,
            })

        # 按置信度排序
        suggestions.sort(key=lambda x: x.get("confidence", 0), reverse=True)
        return suggestions[:20]  # 最多返回20条

    def adapt_threshold(self, event_type: str, new_threshold: float) -> dict:
        """
        调整特定事件类型的风险阈值。

        Args:
            event_type: 事件类型（如 "SHELL_EXECUTE"）
            new_threshold: 新的阈值 (0.0-1.0)

        Returns:
            dict with update result
        """
        old_threshold = self._threshold_overrides.get(event_type)
        self._threshold_overrides[event_type] = max(0.0, min(1.0, new_threshold))

        return {
            "event_type": event_type,
            "old_threshold": old_threshold,
            "new_threshold": new_threshold,
            "updated": True,
        }

    def get_threshold(self, event_type: str) -> float | None:
        """获取事件类型的阈值（若有覆盖）"""
        return self._threshold_overrides.get(event_type)

    def get_stats(self) -> dict:
        """获取学习器统计"""
        return {
            "threshold_overrides": dict(self._threshold_overrides),
            "learned_patterns_count": len(self._learned_patterns),
            "total_events_processed": sum(self._event_count.values()),
            "min_confidence": self._min_confidence,
        }


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
        priority: int = 1,               # P0=0 最高优先级，数字越大优先级越低
    ):
        self.rule_id = rule_id
        self.name = name
        self.action_type = action_type
        self.target_pattern = target_pattern
        self.risk_level = risk_level
        self.decision = decision
        self.reason = reason
        self.enabled = enabled
        self.priority = priority  # P0=0 最高优先级

    def matches(self, action: SafetyAction) -> bool:
        """检查规则是否匹配"""
        if not self.enabled:
            return False
        if self.action_type is not None and action.action_type != self.action_type:
            return False
        if self.target_pattern:
            import fnmatch
            import re
            # Match 1: action.target (primary field, e.g. file path)
            if action.target and fnmatch.fnmatch(action.target, self.target_pattern):
                return True
            # Match 2: SHELL_EXECUTE also checks details[cmd] for the command string
            if action.action_type == ActionType.SHELL_EXECUTE:
                cmd = action.details.get("cmd", "") if action.details else ""
                if cmd:
                    # Try glob match first
                    if fnmatch.fnmatch(cmd, self.target_pattern):
                        return True
                    # Try regex match as fallback (handles patterns like rm -rf /)
                    # Convert glob pattern to regex for path components
                    # ReDoS 防护：用信号量加 1 秒超时（Minsky: 资源边界必须硬编码）
                    try:
                        import signal
                        regex_pattern = fnmatch.translate(self.target_pattern)
                        compiled = re.compile(regex_pattern)

                        def _timeout_handler(signum, frame):
                            raise TimeoutError("Regex timeout")

                        old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
                        signal.alarm(1)  # 1秒超时
                        try:
                            if compiled.search(cmd):
                                signal.alarm(0)
                                return True
                        except TimeoutError:
                            logger.warning(f"Regex timeout for pattern: {self.target_pattern}")
                        finally:
                            signal.alarm(0)
                            signal.signal(signal.SIGALRM, old_handler)
                    except (re.error, OSError):
                        pass  # 忽略无法处理的模式
            # Match 3: pattern is checked against target and (for shell) cmd
            return False
        return True


# ══════════════════════════════════════════════════════════════════════════════
# 任正非 极限生存假设 + 沈昌祥 主动防御
# 华为核心不是技术，而是"假设所有供应链都被切断"的能力
# 安全不是"筑墙"而是"免疫"——系统应该主动识别和消灭威胁
# ══════════════════════════════════════════════════════════════════════════════


class WorstCaseSurvivalMode:
    """
    任正非极限生存假设模式。
    
    核心问题："AgentSafety 是否在假设'最坏情况'下依然能保护系统？"
    
    华为的生存战略：
    - 假设所有外部依赖都被切断
    - 假设攻击者已渗透到内部
    - 假设所有供应链都不可信
    
    这个模式让系统在极端情况下依然保持基本安全能力。
    
    触发条件：
    1. 检测到国家级威胁（Alperovitch）
    2. 供应链攻击确认
    3. 外部依赖全部失效
    4. 连续高风险事件导致熔断
    """
    
    SURVIVAL_OPERATIONS = {
        # 只允许最基本的操作
        ActionType.FILE_READ,   # 只读
        ActionType.HTTP_REQUEST,  # 必要的网络请求
    }
    
    BLOCKED_OPERATIONS = {
        # 危险操作全部阻止
        ActionType.SHELL_EXECUTE,
        ActionType.FILE_EXECUTE,
        ActionType.DATA_DELETE,
        ActionType.DATA_EXPORT,
        ActionType.ENV_WRITE,
    }
    
    def __init__(
        self,
        enabled: bool = False,
        auto_trigger_on_apt: bool = True,
        auto_trigger_on_supply_chain: bool = True,
        auto_trigger_on_circuit_break: bool = True,
    ):
        self._enabled = enabled
        self._auto_trigger_on_apt = auto_trigger_on_apt
        self._auto_trigger_on_supply_chain = auto_trigger_on_supply_chain
        self._auto_trigger_on_circuit_break = auto_trigger_on_circuit_break
        self._activation_reason: str | None = None
    
    @property
    def is_active(self) -> bool:
        return self._enabled
    
    def activate(self, reason: str = "manual"):
        """激活极限生存模式"""
        self._enabled = True
        self._activation_reason = reason
        logger.warning(f"[SurvivalMode] 极限生存模式激活: {reason}")
    
    def deactivate(self):
        """关闭极限生存模式"""
        self._enabled = False
        self._activation_reason = None
        logger.info("[SurvivalMode] 极限生存模式已关闭")
    
    def should_activate(
        self,
        threat_attribution: ThreatAttribution = None,
        is_circuit_broken: bool = False,
    ) -> bool:
        """检查是否应该激活极限生存模式"""
        if self._enabled:
            return True  # 已激活
        
        # 国家级APT攻击：自动激活
        if self._auto_trigger_on_apt and threat_attribution and threat_attribution.is_state_sponsored():
            return True
        
        # 供应链攻击：自动激活
        if self._auto_trigger_on_supply_chain and threat_attribution and threat_attribution.requires_supply_chain_defense():
            return True
        
        # 熔断状态：自动激活
        if self._auto_trigger_on_circuit_break and is_circuit_broken:
            return True
        
        return False
    
    def evaluate_action(self, action: SafetyAction) -> tuple[bool, str]:
        """
        在极限生存模式下评估 Action。
        
        Returns:
            (allowed, reason)
        """
        if not self._enabled:
            return True, "normal"
        
        # 白名单操作：允许
        if action.action_type in self.SURVIVAL_OPERATIONS:
            return True, f"survival_mode: {action.action_type.value} is essential"
        
        # 危险操作：阻止
        if action.action_type in self.BLOCKED_OPERATIONS:
            return False, f"survival_mode: {action.action_type.value} blocked in survival mode"
        
        # 其他操作：需要显式允许
        return False, f"survival_mode: {action.action_type.value} not allowed in survival mode"
    
    def get_status(self) -> dict:
        return {
            "active": self._enabled,
            "reason": self._activation_reason,
            "allowed_ops": [op.value for op in self.SURVIVAL_OPERATIONS],
            "blocked_ops": [op.value for op in self.BLOCKED_OPERATIONS],
        }


class ActiveThreatSensor:
    """
    沈昌祥主动防御：系统应该能够主动识别和消灭威胁。
    
    问题："AgentSafety 是否在被动的规则匹配，还是有主动的威胁感知？"
    
    主动防御不同于被动规则匹配：
    - 被动：已知规则匹配才拦截
    - 主动：异常行为模式自动触发警报
    
    感知维度：
    1. 行为异常检测（baseline deviation）
    2. 频率异常（请求频率突然变化）
    3. 时序异常（操作在非正常时间发生）
    4. 关联异常（多个低风险操作组合成高风险）
    5. 威胁情报关联（已知恶意 IP/行为模式）
    """
    
    def __init__(
        self,
        baseline_window: int = 100,      # 基线窗口大小
        anomaly_threshold: float = 2.5,   # 异常检测阈值（标准差倍数）
        frequency_spike_multiplier: float = 3.0,  # 频率突增倍数
        correlation_window_seconds: float = 60.0,  # 关联分析窗口
    ):
        self._baseline_window = baseline_window
        self._anomaly_threshold = anomaly_threshold
        self._frequency_spike_multiplier = frequency_spike_multiplier
        self._correlation_window = correlation_window_seconds
        
        # 基线数据：每个 action_type 的正常行为范围
        self._action_baseline: dict[ActionType, dict] = {}
        
        # 频率追踪
        self._action_frequency: dict[str, list[float]] = {}  # action_type -> [timestamps]
        
        # 关联分析窗口
        self._recent_actions: list[SafetyAction] = []
        
        # 威胁情报（简化版：已知恶意 IP/模式）
        self._threat_intel: dict[str, float] = {}  # IP/pattern -> threat_score
    
    def update_baseline(self, action: SafetyAction):
        """更新行为基线"""
        at = action.action_type
        if at not in self._action_baseline:
            self._action_baseline[at] = {
                "scores": [],
                "targets": set(),
                "hourly_distribution": defaultdict(int),
            }
        
        baseline = self._action_baseline[at]
        baseline["scores"].append(action.risk_score)
        if action.target:
            baseline["targets"].add(action.target)
        
        # 更新时间分布
        import datetime
        hour = datetime.datetime.fromtimestamp(action.timestamp).hour
        baseline["hourly_distribution"][hour] += 1
        
        # 保持窗口大小
        if len(baseline["scores"]) > self._baseline_window:
            baseline["scores"] = baseline["scores"][-self._baseline_window:]
    
    def detect_anomaly(self, action: SafetyAction) -> tuple[bool, float, str]:
        """
        主动异常检测。
        
        Returns:
            (is_anomaly, anomaly_score, anomaly_type)
        """
        if action.action_type not in self._action_baseline:
            return False, 0.0, "no_baseline"
        
        baseline = self._action_baseline[action.action_type]
        scores = baseline["scores"]
        if len(scores) < 10:
            return False, 0.0, "insufficient_baseline"
        
        # 计算基线统计
        mean_score = sum(scores) / len(scores)
        variance = sum((s - mean_score) ** 2 for s in scores) / len(scores)
        std_dev = variance ** 0.5
        
        # 检测风险评分异常
        if std_dev > 0:
            z_score = abs(action.risk_score - mean_score) / std_dev
            if z_score > self._anomaly_threshold:
                return True, z_score, f"risk_score_anomaly (z={z_score:.1f})"
        
        # 检测目标异常（之前没见过这个目标）
        if action.target and action.target not in baseline["targets"]:
            # 新目标但高风险：可疑
            if action.risk_score > 0.5:
                return True, 0.8, "novel_high_risk_target"
        
        return False, 0.0, "normal"
    
    def detect_frequency_spike(self, action: SafetyAction) -> tuple[bool, float]:
        """
        检测频率突增。
        
        Returns:
            (is_spike, spike_ratio)
        """
        key = f"{action.agent_id}:{action.action_type.value}"
        now = time.time()
        
        if key not in self._action_frequency:
            self._action_frequency[key] = []
        
        # 清理过期记录
        recent_window = now - 60  # 1分钟
        self._action_frequency[key] = [
            t for t in self._action_frequency[key] if t > recent_window
        ]
        
        current_count = len(self._action_frequency[key])
        self._action_frequency[key].append(now)
        
        # 计算平均频率
        if len(scores_for_key := self._action_frequency.get(key, [])) < 10:
            return False, 0.0
        
        # 简单基线：每小时动作数
        baseline_rate = len(scores_for_key) / max(1, (now - scores_for_key[0]) / 3600)
        current_rate = current_count / 1  # 当前是1分钟内的计数
        
        if baseline_rate > 0 and current_rate / baseline_rate > self._frequency_spike_multiplier:
            return True, current_rate / baseline_rate
        
        return False, 0.0
    
    def analyze_correlation(self, action: SafetyAction) -> tuple[bool, float, str]:
        """
        关联分析：多个低风险操作组合成高风险。
        
        例如：
        - 连续 FILE_READ + ENV_READ + DATA_EXPORT = 数据窃取
        - 连续 SHELL_EXECUTE + FILE_DELETE = 破坏痕迹
        
        Returns:
            (is_high_risk_correlation, correlation_score, pattern_name)
        """
        now = time.time()
        
        # 加入当前action
        self._recent_actions.append(action)
        
        # 清理过期
        self._recent_actions = [
            a for a in self._recent_actions
            if now - a.timestamp < self._correlation_window
        ]
        
        # 定义危险模式
        danger_patterns = [
            {
                "name": "data_exfiltration",
                "actions": {ActionType.ENV_READ, ActionType.FILE_READ, ActionType.DATA_EXPORT},
                "min_sequence": 3,
            },
            {
                "name": "destructive_chain",
                "actions": {ActionType.SHELL_EXECUTE, ActionType.FILE_DELETE, ActionType.DATA_DELETE},
                "min_sequence": 2,
            },
            {
                "name": "privilege_escalation",
                "actions": {ActionType.ENV_READ, ActionType.ENV_WRITE, ActionType.SHELL_EXECUTE},
                "min_sequence": 3,
            },
        ]
        
        for pattern in danger_patterns:
            pattern_actions = [a for a in self._recent_actions if a.action_type in pattern["actions"]]
            if len(pattern_actions) >= pattern["min_sequence"]:
                # 计算这个组合的总风险
                total_risk = sum(a.risk_score for a in pattern_actions)
                avg_risk = total_risk / len(pattern_actions)
                
                # 组合风险 > 各部分之和（协同放大效应）
                individual_max = max(a.risk_score for a in pattern_actions)
                synergy_factor = 1.5  # 协同放大系数
                
                if total_risk > individual_max * synergy_factor:
                    return True, total_risk, pattern["name"]
        
        return False, 0.0, "none"
    
    def check_threat_intel(self, action: SafetyAction) -> tuple[bool, float, str]:
        """
        威胁情报关联。
        
        检查：
        1. source_ip 是否在威胁情报黑名单
        2. target 是否在恶意目标列表
        """
        # 检查 source_ip
        if action.source_ip and action.source_ip in self._threat_intel:
            score = self._threat_intel[action.source_ip]
            return True, score, f"malicious_ip:{action.source_ip}"
        
        # 检查 target
        if action.target and action.target in self._threat_intel:
            score = self._threat_intel[action.target]
            return True, score, f"malicious_target:{action.target}"
        
        return False, 0.0, "clean"
    
    def add_threat_intel(self, indicator: str, threat_score: float):
        """添加威胁情报"""
        self._threat_intel[indicator] = threat_score
    
    def sense(self, action: SafetyAction) -> dict:
        """
        综合主动感知。
        
        Returns:
            dict with:
            - is_anomalous: 是否异常
            - threat_level: 0-1 综合威胁等级
            - threat_types: 检测到的威胁类型列表
            - recommendations: 建议
        """
        threats = []
        threat_level = 0.0
        
        # 1. 异常行为检测
        is_anomaly, anomaly_score, anomaly_type = self.detect_anomaly(action)
        if is_anomaly:
            threats.append(f"anomaly:{anomaly_type}")
            threat_level = max(threat_level, min(anomaly_score / 5.0, 1.0))
        
        # 2. 频率突增检测
        is_spike, spike_ratio = self.detect_frequency_spike(action)
        if is_spike:
            threats.append(f"frequency_spike:{spike_ratio:.1f}x")
            threat_level = max(threat_level, min(spike_ratio / 10.0, 1.0))
        
        # 3. 关联分析
        is_correlated, corr_score, corr_pattern = self.analyze_correlation(action)
        if is_correlated:
            threats.append(f"correlation:{corr_pattern}")
            threat_level = max(threat_level, min(corr_score / 5.0, 1.0))
        
        # 4. 威胁情报
        is_intel_match, intel_score, intel_type = self.check_threat_intel(action)
        if is_intel_match:
            threats.append(f"threat_intel:{intel_type}")
            threat_level = max(threat_level, intel_score)
        
        # 更新基线
        self.update_baseline(action)
        
        recommendations = []
        if threat_level > 0.7:
            recommendations.append("立即人工审查")
        elif threat_level > 0.4:
            recommendations.append("增强监控")
        
        return {
            "is_anomalous": len(threats) > 0,
            "threat_level": round(threat_level, 3),
            "threat_types": threats,
            "recommendations": recommendations,
        }


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
        # Graham 安全边际配置
        margin_block: float = 0.30,
        margin_warn: float = 0.15,
        # Jones 非对称风险配置
        unknown_penalty: float = 2.5,
        uncertainty_cb_threshold: float = 0.7,
    ):
        from .policies import default_policies
        self._rules = rules or [PolicyRule(**p) for p in default_policies]
        self._llm_judge = llm_judge
        self._middlewares: list[Callable] = []
        self._decision_history: list[SafetyDecision] = []  # 决策历史

        # 熔断器状态
        self._cb_threshold = circuit_breaker_threshold
        self._cb_window = circuit_breaker_window
        self._cb_events: list[float] = []  # 时间戳列表
        self._cb_open = False
        self._cb_opened_at: float | None = None

        # ── 格雷厄姆安全边际计算机 ──────────────────────────────
        self._margin_calc = MarginCalculator(
            block_margin=margin_block,
            warn_margin=margin_warn,
            cost_fn=10.0,   # Graham: 漏报成本 >> 误报成本
            cost_fp=1.0,
        )

        # ── 琼斯非对称风险管理器 ────────────────────────────────
        self._asymmetric_mgr = AsymmetricRiskManager(
            unknown_threat_penalty=unknown_penalty,
            uncertainty_cb_threshold=uncertainty_cb_threshold,
        )

        # ── 西蒙斯信号/噪声分离器（用于决策置信度追踪）──────────
        self._snr_separator = SignalNoiseSeparator()

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

    def _compute_recent_variance(self) -> float:
        """
        计算最近决策的方差（用于判断系统不确定性）。
        西蒙斯思路：高方差意味着系统对风险判断不一致 = 更多噪声。
        """
        if len(self._decision_history) < 5:
            return 0.0

        recent = self._decision_history[-20:]
        scores = [d.risk_score for d in recent]
        if not scores:
            return 0.0

        mean = sum(scores) / len(scores)
        variance = sum((s - mean) ** 2 for s in scores) / len(scores)
        return min(variance, 1.0)  # 归一化到 [0, 1]

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
        # ── 格雷厄姆安全边际 + 琼斯非对称风险 ────────────────
        is_known_pattern = len(matched_rules) > 0

        if override_decision:
            # 有规则匹配：已知模式
            risk_level = override_level or RiskLevel.HIGH
            final_decision = override_decision
            reason = override_reason or ""

            # Graham: 对已知模式应用安全边际计算
            margin = self._margin_calc.compute_margin(base_score, is_known_pattern=True)
            expected_loss = self._margin_calc.expected_cost(base_score, is_known=True)

            # Jones: 已知模式使用标准处理
            confidence = 0.8 if is_known_pattern else 0.5
        else:
            # 无规则匹配：未知模式 = 未知威胁
            # Jones 非对称保护：未知威胁自动惩罚
            pattern_confidence = 0.3  # 未知模式低置信度

            # 计算决策历史方差（高方差=不确定）
            history_variance = self._compute_recent_variance()

            # Jones: 非对称风险评分
            adjusted_score = self._asymmetric_mgr.compute_asymmetric_score(
                base_score=base_score,
                is_known_threat=False,
                pattern_confidence=pattern_confidence,
                decision_history_variance=history_variance,
            )

            # Graham: 安全边际决策（基于调整后评分）
            final_decision, risk_level, margin = self._margin_calc.decision_with_margin(
                score=adjusted_score,
                is_known_pattern=False,
                dry_run=action.dry_run,
            )

            # 构建理由
            if final_decision == "BLOCK":
                reason = f"未知操作+非对称保护（评分 {adjusted_score:.2f}），自动拦截"
            elif final_decision == "WARN":
                reason = f"未知操作，建议人工确认（评分 {adjusted_score:.2f}）"
            else:
                reason = f"未知操作，低风险放行（评分 {adjusted_score:.2f}）"

            expected_loss = self._margin_calc.expected_cost(adjusted_score, is_known=False)
            confidence = pattern_confidence

        # ── 西蒙斯 SNR：记录决策置信度 ─────────────────────────
        self._asymmetric_mgr.record_decision_confidence(confidence)

        # ── 格雷厄姆防御性检查 ─────────────────────────────────
        # 防御性原则：先保证不漏掉真正威胁，再考虑误报
        # 如果 expected_loss 超过阈值，强制提升为 BLOCK
        if expected_loss > 5.0 and final_decision in ("ALLOW", "WARN"):
            final_decision = "BLOCK"
            risk_level = RiskLevel.HIGH
            reason += "（期望损失过高，防御性拦截）"

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

        decision = SafetyDecision(
            action_id=action.action_id,
            risk_level=risk_level,
            decision=final_decision,
            reason=reason,
            risk_score=base_score,
            matched_policies=matched_rules,
            timestamp=time.time(),
            metadata={
                "safety_margin": round(margin, 3),
                "expected_loss": round(expected_loss, 3),
                "is_known_pattern": is_known_pattern,
                "confidence": round(confidence, 3),
                "defensive_bias": self._margin_calc.get_defensive_bias(),
            },
        )

        # 记录到历史
        self._decision_history.append(decision)

        return decision

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
        """获取安全统计（包含三位一体风险框架状态）"""
        return {
            "total_rules": len(self._rules),
            "circuit_breaker_open": self._cb_open,
            "risk_events_in_window": len(self._cb_events),
            "middlewares_count": len(self._middlewares),
            # Graham 安全边际状态
            "graham_margin": {
                "defensive_bias": self._margin_calc.get_defensive_bias(),
                "cost_fn": self._margin_calc.COST_FN,
                "cost_fp": self._margin_calc.COST_FP,
            },
            # Jones 非对称风险状态
            "jones_asymmetric": self._asymmetric_mgr.get_protection_report(),
            # Simons SNR 状态
            "simons_snr": self._snr_separator.get_signal_stats(),
        }

    def get_risk_framework_report(self) -> dict:
        """
        获取三位一体风险管理框架的完整报告。

        Graham: 安全边际是否足够？
        Simons: 决策中噪声比例有多少？
        Jones: 未知威胁是否有足够保护？
        """
        # Graham: 计算当前平均安全边际
        margins = []
        for d in self._decision_history[-50:]:
            m = d.metadata.get("safety_margin", 0.5)
            margins.append(m)
        avg_margin = sum(margins) / len(margins) if margins else 0.5

        # Jones: 未知威胁保护状态
        jones_report = self._asymmetric_mgr.get_protection_report()

        # Simons: 决策置信度分布
        confidences = [d.metadata.get("confidence", 0.5) for d in self._decision_history[-50:]]
        avg_conf = sum(confidences) / len(confidences) if confidences else 0.5

        # 高噪声决策比例
        noise_decisions = sum(1 for c in confidences if c < 0.4)
        noise_ratio = noise_decisions / len(confidences) if confidences else 0.0

        return {
            "graham_safety_margin": {
                "avg_margin": round(avg_margin, 3),
                "margin_threshold_block": self._margin_calc._block_margin,
                "margin_threshold_warn": self._margin_calc._warn_margin,
                "defensive_bias": self._margin_calc.get_defensive_bias(),
                "cost_fn_to_fp_ratio": round(self._margin_calc.COST_FN / self._margin_calc.COST_FP, 1),
                "interpretation": "高边际=更安全，低边际=更危险",
            },
            "simons_signal_noise": {
                "avg_confidence": round(avg_conf, 3),
                "noise_decision_ratio": round(noise_ratio, 3),
                "noise_decisions_count": noise_decisions,
                "interpretation": "高噪声比=决策质量不稳定",
            },
            "jones_asymmetric_protection": {
                "unknown_penalty": jones_report["unknown_threat_penalty"],
                "uncertainty_cb_threshold": jones_report["uncertainty_cb_threshold"],
                "current_avg_uncertainty": jones_report["current_avg_uncertainty"],
                "should_cb_on_uncertainty": jones_report["should_cb_on_uncertainty"],
                "interpretation": "未知惩罚越高=对未知威胁越保守",
            },
            "recommendations": self._generate_framework_recommendations(
                avg_margin, noise_ratio, jones_report
            ),
        }

    def _generate_framework_recommendations(
        self, avg_margin: float, noise_ratio: float, jones_report: dict
    ) -> list[str]:
        """基于三位一体框架给出改进建议"""
        recs = []

        # Graham 边际检查
        if avg_margin < 0.15:
            recs.append("Graham: 安全边际不足，建议收紧 BLOCK/WARN 阈值")
        elif avg_margin > 0.35:
            recs.append("Graham: 安全边际充足，系统偏保守")

        # Simons 噪声检查
        if noise_ratio > 0.3:
            recs.append("Simons: 噪声决策比例过高(>30%)，建议审查决策模式")
        if jones_report["should_cb_on_uncertainty"]:
            recs.append("Jones: 不确定性熔断即将触发，建议增加已知规则覆盖")

        # Jones 非对称保护检查
        if jones_report["current_avg_uncertainty"] > 0.5:
            recs.append("Jones: 当前决策不确定性较高，对未知威胁保持警惕")

        return recs if recs else ["三位一体框架运行正常"]

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

    def get_prometheus_metrics(self) -> dict:
        """
        获取 Prometheus 格式的监控指标。

        Returns:
            dict with metric_name -> value mappings suitable for Prometheus pushgateway.
        """
        # 统计各决策类型的计数
        decision_counts = defaultdict(int)
        risk_level_counts = defaultdict(int)

        for decision in self._decision_history:
            decision_counts[decision.decision] += 1
            risk_level_counts[decision.risk_level.name] += 1

        metrics = {
            # 基础统计
            "agent_safety_rules_total": len(self._rules),
            "agent_safety_middlewares_total": len(self._middlewares),
            "agent_safety_circuit_breaker_open": 1 if self._cb_open else 0,
            "agent_safety_risk_events_in_window": len(self._cb_events),
            # 决策统计
            "agent_safety_decision_total": sum(decision_counts.values()),
            "agent_safety_decision_allow_total": decision_counts.get("ALLOW", 0),
            "agent_safety_decision_warn_total": decision_counts.get("WARN", 0),
            "agent_safety_decision_block_total": decision_counts.get("BLOCK", 0),
            "agent_safety_decision_circuit_break_total": decision_counts.get("CIRCUIT_BREAK", 0),
            # 风险等级统计
            "agent_safety_risk_none_total": risk_level_counts.get("NONE", 0),
            "agent_safety_risk_low_total": risk_level_counts.get("LOW", 0),
            "agent_safety_risk_medium_total": risk_level_counts.get("MEDIUM", 0),
            "agent_safety_risk_high_total": risk_level_counts.get("HIGH", 0),
            "agent_safety_risk_critical_total": risk_level_counts.get("CRITICAL", 0),
            # 按优先级统计规则
            "agent_safety_rules_p0_total": sum(1 for r in self._rules if r.priority == 0),
            "agent_safety_rules_p1_total": sum(1 for r in self._rules if r.priority == 1),
            "agent_safety_rules_p2_total": sum(1 for r in self._rules if r.priority >= 2),
        }
        return metrics

    # ══════════════════════════════════════════════════════════════
    # 2026-06-24 主动防御层：芒格逆向思维 + 富兰克林勤勉法
    # ══════════════════════════════════════════════════════════════

    def get_attack_surface(self) -> dict:
        """
        芒格式逆向思维攻击面分析。

        核心问题："我最害怕什么？什么东西会让我失败？"

        枚举所有可能的攻击向量，按严重度排序。
        """
        attack_vectors = []

        # 向量1：凭证泄露
        credential_actions = [
            ActionType.ENV_READ, ActionType.DATA_EXPORT,
        ]
        for at in credential_actions:
            attack_vectors.append({
                "vector_id": f"cred_leak_{at.value}",
                "type": "凭证泄露",
                "action_type": at.value,
                "severity": 9.0,
                "likelihood": "中",
                "impact": "攻击者获取敏感凭证",
                "mitigation": "凭证不得出现在日志/响应中，实施最小权限",
            })

        # 向量2：命令注入
        attack_vectors.append({
            "vector_id": "cmd_injection",
            "type": "命令注入",
            "action_type": ActionType.SHELL_EXECUTE.value,
            "severity": 9.5,
            "likelihood": "高",
            "impact": "在宿主机上执行任意命令",
            "mitigation": "所有 shell 命令必须经过元字符白名单检测",
        })

        # 向量3：路径遍历
        for at in [ActionType.FILE_READ, ActionType.FILE_WRITE]:
            attack_vectors.append({
                "vector_id": f"path_traversal_{at.value}",
                "type": "路径遍历",
                "action_type": at.value,
                "severity": 8.0,
                "likelihood": "中",
                "impact": "读写禁止目录外的文件",
                "mitigation": "所有路径必须经过 realpath() 边界检查",
            })

        # 向量4：权限升级
        attack_vectors.append({
            "vector_id": "privilege_escalation",
            "type": "权限升级",
            "action_type": ActionType.AGENT_SPAWN.value,
            "severity": 8.5,
            "likelihood": "低",
            "impact": "新 Agent 以更高权限执行",
            "mitigation": "Agent spawn 必须经过明确授权和安全上下文验证",
        })

        # 向量5：数据删除
        attack_vectors.append({
            "vector_id": "data_destruction",
            "type": "数据销毁",
            "action_type": ActionType.DATA_DELETE.value,
            "severity": 9.0,
            "likelihood": "低",
            "impact": "不可逆数据丢失",
            "mitigation": "DATA_DELETE 必须经过二次确认和备份验证",
        })

        # 向量6：外部数据泄露
        attack_vectors.append({
            "vector_id": "data_exfiltration",
            "type": "数据外泄",
            "action_type": ActionType.DATA_EXPORT.value,
            "severity": 8.5,
            "likelihood": "中",
            "impact": "敏感数据被传输到外部",
            "mitigation": "DATA_EXPORT 必须经过 DLP 扫描和目标地址白名单",
        })

        # 向量7：恶意 DNS 解析
        attack_vectors.append({
            "vector_id": "dns_rebinding",
            "type": "DNS 重绑定",
            "action_type": ActionType.DNS_LOOKUP.value,
            "severity": 7.0,
            "likelihood": "低",
            "impact": "绕过同源策略，访问内部服务",
            "mitigation": "DNS 解析结果必须经过 TTL 验证和 IP 范围检查",
        })

        # 按严重度排序
        attack_vectors.sort(key=lambda v: -v["severity"])
        return {
            "total_vectors": len(attack_vectors),
            "critical_count": sum(1 for v in attack_vectors if v["severity"] >= 9.0),
            "high_count": sum(1 for v in attack_vectors if 8.0 <= v["severity"] < 9.0),
            "attack_vectors": attack_vectors,
            "analysis_date": datetime.now().isoformat(),
        }

    def get_security_posture_score(self) -> float:
        """
        富兰克林勤勉法：量化安全态势评分（0-10）。

        基于以下维度：
        1. 规则完整性（是否有 P0 规则覆盖所有攻击向量）
        2. 熔断器健康度（是否经常触发）
        3. 决策历史覆盖率（有多少决策有完整日志）
        4. 高风险操作拦截率
        """
        score = 5.0  # 基础分

        # 规则覆盖率
        critical_vectors = self.get_attack_surface()
        covered = 0
        for vec in critical_vectors["attack_vectors"]:
            for rule in self._rules:
                if rule.enabled and rule.action_type and rule.action_type.value == vec["action_type"]:
                    covered += 1
                    break
        coverage_ratio = covered / max(critical_vectors["total_vectors"], 1)
        score += coverage_ratio * 2.0  # 最多+2分

        # 熔断器健康度
        if not self._cb_open:
            score += 1.0  # 熔断器未触发 +1分
        if self._cb_threshold > 0 and len(self._cb_events) < self._cb_threshold:
            score += 0.5  # 远离熔断阈值 +0.5分

        # 决策历史完整性
        if len(self._decision_history) > 10:
            high_risk = sum(1 for d in self._decision_history[-100:]
                           if d.risk_level.value >= RiskLevel.HIGH.value)
            if high_risk > 0:
                # 高风险操作被 BLOCK/WARN 的比例
                blocked = sum(1 for d in self._decision_history[-100:]
                            if d.risk_level.value >= RiskLevel.HIGH.value
                            and d.decision in ("BLOCK", "WARN"))
                block_ratio = blocked / high_risk
                score += block_ratio * 1.5  # 最多+1.5分

        return min(10.0, round(score, 2))

    def get_security_invariants(self) -> list[dict]:
        """
        安全不变量：必须始终为真的安全断言。

        这些不变量被违反时，系统必须 fail-safe。
        """
        invariants = [
            {
                "id": "no_raw_credential_in_response",
                "description": "API 响应中不得包含明文凭证（API key/token/password）",
                "check": "ENV_READ / DATA_EXPORT 操作不得在响应中返回原始值",
                "status": "unknown",
                "last_checked": None,
            },
            {
                "id": "shell_meta_char_whitelist",
                "description": "所有 SHELL_EXECUTE 必须经过元字符白名单",
                "check": "检查所有 shell 执行是否有 meta_char 检测",
                "status": "unknown",
                "last_checked": None,
            },
            {
                "id": "path_boundary_enforcement",
                "description": "所有文件操作必须验证路径边界",
                "check": "所有 FILE_READ/WRITE 必须有 realpath 边界检查",
                "status": "unknown",
                "last_checked": None,
            },
            {
                "id": "circuit_breaker_functional",
                "description": "熔断器在连续高风险事件后必须触发",
                "check": f"当前窗口 {len(self._cb_events)}/{self._cb_threshold}",
                "status": "ok" if len(self._cb_events) < self._cb_threshold else "warning",
                "last_checked": time.time(),
            },
            {
                "id": "p0_rules_always_enabled",
                "description": "所有 P0 规则必须始终启用",
                "check": f"P0规则数量: {sum(1 for r in self._rules if r.priority == 0 and r.enabled)}",
                "status": "ok" if all(r.enabled for r in self._rules if r.priority == 0) else "critical",
                "last_checked": time.time(),
            },
        ]
        return invariants


from datetime import datetime


# ══════════════════════════════════════════════════════════════════════════════
# 任正非灰度理论 - GraduatedDecisionEngine
# 替代二元 BLOCK/WARN 决策，用7级渐进式响应
# ══════════════════════════════════════════════════════════════════════════════


class GraduatedResponse(Enum):
    """7级渐进式响应（任正非灰度理论）"""
    FULL_ALLOW = "full_allow"        # 0.0-0.2 完全放行
    SANDBOX = "sandbox"              # 0.2-0.4 沙盒执行
    RATE_LIMITED = "rate_limited"    # 0.4-0.5 限流
    WARN = "warn"                    # 0.5-0.7 警告
    BLOCK = "block"                  # 0.7-0.85 阻止
    CIRCUIT_BREAK = "circuit_break"  # 0.85-0.95 熔断
    EMERGENCY_LOCK = "emergency_lock"  # 0.95-1.0 紧急锁定


class GraduatedDecisionEngine:
    """
    任正非灰度理论决策引擎。
    
    核心理念：
    - 不是非黑即白，而是渐进式响应
    - 根据风险评分动态调整防护级别
    - 给未知威胁更多观察空间，同时对高风险快速响应
    
    与 SafetyEngine.evaluate() 配合使用，提供更细粒度的决策。
    """

    # 分数区间阈值
    THRESHOLDS = {
        GraduatedResponse.FULL_ALLOW: (0.0, 0.2),
        GraduatedResponse.SANDBOX: (0.2, 0.4),
        GraduatedResponse.RATE_LIMITED: (0.4, 0.5),
        GraduatedResponse.WARN: (0.5, 0.7),
        GraduatedResponse.BLOCK: (0.7, 0.85),
        GraduatedResponse.CIRCUIT_BREAK: (0.85, 0.95),
        GraduatedResponse.EMERGENCY_LOCK: (0.95, 1.0),
    }

    # 已知/未知模式的分数偏移（未知模式更保守）
    UNKNOWN_BIAS = 0.1

    # 需要审计的响应级别
    AUDIT_REQUIRED = {
        GraduatedResponse.WARN,
        GraduatedResponse.BLOCK,
        GraduatedResponse.CIRCUIT_BREAK,
        GraduatedResponse.EMERGENCY_LOCK,
    }

    def __init__(self):
        # 跟踪连续触发次数（用于升级路径）
        self._consecutive_counts: dict[GraduatedResponse, int] = defaultdict(int)
        # 升级计数器阈值
        self.ESCALATION_THRESHOLDS = {
            GraduatedResponse.WARN: 3,      # WARN 3次 → BLOCK
            GraduatedResponse.SANDBOX: 5,   # SANDBOX 5次 → RATE_LIMITED
            GraduatedResponse.RATE_LIMITED: 3,  # RATE_LIMITED 3次 → WARN
        }

    def map_score_to_response(self, score: float, is_known: bool = True) -> GraduatedResponse:
        """
        将风险评分映射到7级响应。
        
        Args:
            score: 风险评分 0.0-1.0
            is_known: 是否为已知威胁模式
            
        Returns:
            对应的 GraduatedResponse 级别
        """
        # 未知模式分数上调（更保守）
        effective_score = score + (self.UNKNOWN_BIAS if not is_known else 0.0)
        effective_score = min(1.0, effective_score)

        # 查找对应的响应级别
        for response, (low, high) in self.THRESHOLDS.items():
            if low <= effective_score < high:
                return response
        
        # 边界情况：恰好是1.0
        return GraduatedResponse.EMERGENCY_LOCK

    def get_response_description(self, response: GraduatedResponse) -> str:
        """
        返回人类可读的响应级别说明。
        
        Args:
            response: GraduatedResponse 枚举值
            
        Returns:
            描述字符串
        """
        descriptions = {
            GraduatedResponse.FULL_ALLOW: "完全放行：风险极低，正常执行",
            GraduatedResponse.SANDBOX: "沙盒执行：隔离环境监控执行，限制资源访问",
            GraduatedResponse.RATE_LIMITED: "限流执行：降低操作频率，增加人工审核",
            GraduatedResponse.WARN: "警告拦截：记录日志并通知，需要确认后放行",
            GraduatedResponse.BLOCK: "阻止执行：拒绝执行，触发安全告警",
            GraduatedResponse.CIRCUIT_BREAK: "熔断保护：暂停所有高风险操作，进入维护模式",
            GraduatedResponse.EMERGENCY_LOCK: "紧急锁定：系统级冻结，需要安全团队介入解锁",
        }
        return descriptions.get(response, "未知响应")

    def should_audit(self, response: GraduatedResponse) -> bool:
        """
        判断该响应级别是否需要审计日志。
        
        Args:
            response: GraduatedResponse 枚举值
            
        Returns:
            True 如果需要审计
        """
        return response in self.AUDIT_REQUIRED

    def get_escalation_path(self, response: GraduatedResponse) -> Optional[GraduatedResponse]:
        """
        获取升级路径（例如 WARN 3次 → BLOCK）。
        
        Args:
            response: 当前响应级别
            
        Returns:
            升级后的响应级别，如果已达最高返回 None
        """
        escalation_map = {
            GraduatedResponse.FULL_ALLOW: None,
            GraduatedResponse.SANDBOX: GraduatedResponse.RATE_LIMITED,
            GraduatedResponse.RATE_LIMITED: GraduatedResponse.WARN,
            GraduatedResponse.WARN: GraduatedResponse.BLOCK,
            GraduatedResponse.BLOCK: GraduatedResponse.CIRCUIT_BREAK,
            GraduatedResponse.CIRCUIT_BREAK: GraduatedResponse.EMERGENCY_LOCK,
            GraduatedResponse.EMERGENCY_LOCK: None,  # 已达最高
        }
        return escalation_map.get(response)

    def record_response(self, response: GraduatedResponse) -> Optional[GraduatedResponse]:
        """
        记录响应并检查是否需要升级。
        
        Args:
            response: 当前响应级别
            
        Returns:
            如果触发升级条件，返回升级后的响应；否则返回 None
        """
        # 重置比当前级别低的计数器
        for resp in GraduatedResponse:
            if resp.value < response.value:
                self._consecutive_counts[resp] = 0

        # 增加当前级别计数
        self._consecutive_counts[response] += 1

        # 检查是否触发升级
        threshold = self.ESCALATION_THRESHOLDS.get(response)
        if threshold and self._consecutive_counts[response] >= threshold:
            escalated = self.get_escalation_path(response)
            if escalated:
                # 重置计数器
                self._consecutive_counts[response] = 0
                return escalated
        
        return None

    def reset_counts(self):
        """重置所有计数器（通常在系统重置时调用）"""
        self._consecutive_counts.clear()


# ══════════════════════════════════════════════════════════════════════════════
# Alperovitch 地缘政治威胁归因 - ThreatAttribution
# 对每个威胁进行统计分析归因（不保证准确性）
# ══════════════════════════════════════════════════════════════════════════════


@dataclass
class ThreatIndicator:
    """
    威胁指标数据类（统计分析推测，不是确凿事实！）。
    
    注意：
    - country/actor_type 只是概率推测
    - 置信度低于0.3时不报告具体归因
    """
    source_ip: Optional[str] = None
    actor_type: Optional[str] = None  # APT/脚本小子/内部人员/自动化
    country: Optional[str] = None
    motive: Optional[str] = None  # 金钱/政治/黑客行动/工业间谍
    confidence: float = 0.0  # 归因置信度 0.0-1.0
    attribution_method: str = "unknown"  # 归因方法


class ThreatProfiler:
    """
    威胁归因分析器（Alperovitch 地缘政治模型）。
    
    统计分析方法，推测攻击者类型和动机。
    置信度低于0.3时不报告具体归因，防止误导。
    
    注意：只做统计分析，不做真实溯源！
    """

    # 常见攻击模式 → 攻击者类型映射
    ACTOR_PATTERNS = {
        "script_kiddie": {
            "patterns": ["simple", "brute_force", "well_known", "basic"],
            "indicators": ["low_variance", "repeated_same", "single_vector"],
        },
        "automated": {
            "patterns": ["scanner", "bot", "mass_scan", "automated"],
            "indicators": ["high_frequency", "uniform", "no_adaptation"],
        },
        "insider": {
            "patterns": ["privilege_escalation", "data_theft", "lateral_movement"],
            "indicators": ["legitimate_access", "after_hours", "unusual_target"],
        },
        "apt": {
            "patterns": ["stealth", "persistence", "lateral_movement", "data_exfil"],
            "indicators": ["low_frequency", "adaptive", "custom_tool", "multi_stage"],
        },
    }

    # 动机特征
    MOTIVE_PATTERNS = {
        "financial": {
            "actions": ["DATA_EXPORT", "ENV_READ", "CREDENTIAL_READ"],
            "indicators": ["targeted_data", "personal_info", "payment"],
        },
        "political": {
            "actions": ["FILE_DELETE", "SERVICE_STOP", "CONFIG_CHANGE"],
            "indicators": ["disruption", "propaganda", "defacement"],
        },
        "hacktivism": {
            "actions": ["PUBLIC_ACTION", "MESSAGE_INJECTION"],
            "indicators": ["political_statement", "cause_advocacy", "public"],
        },
        "industrial_espionage": {
            "actions": ["CODE_READ", "FILE_READ", "DATA_EXPORT"],
            "indicators": ["technical_data", "proprietary", "competitor_target"],
        },
    }

    # 国家/地区 TLD 映射（简化版）
    IP_REGION_HINTS = {
        ".cn": "China",
        ".ru": "Russia",
        ".kp": "North Korea",
        ".ir": "Iran",
        ".br": "Brazil",
        ".in": "India",
        ".pk": "Pakistan",
        ".vn": "Vietnam",
        ".kp": "North Korea",
    }

    def __init__(self):
        self._attribution_history: list[ThreatIndicator] = []

    def attribute_threat(self, action: dict) -> ThreatIndicator:
        """
        对威胁进行归因分析。
        
        Args:
            action: SafetyEngine.evaluate() 返回的 action 字典
            
        Returns:
            ThreatIndicator 对象（置信度可能很低）
        """
        # 提取基本信息
        source_ip = action.get("source_ip") or action.get("ip")
        action_type = action.get("action_type", "")
        risk_score = action.get("risk_score", 0.5)
        pattern = action.get("pattern") or action.get("matched_pattern")
        
        # 推断攻击者类型
        actor_type, actor_conf = self._infer_actor_from_pattern(action)
        
        # 推断动机
        motive, motive_conf = self._infer_motive_from_context(action)
        
        # 推断国家（如果有 IP）
        country = self._infer_country_from_ip(source_ip) if source_ip else None
        
        # 综合置信度
        confidence = self._compute_confidence(
            actor_conf, motive_conf, bool(source_ip), bool(pattern)
        )
        
        # 构建归因对象
        attribution = ThreatIndicator(
            source_ip=source_ip,
            actor_type=actor_type if confidence >= 0.3 else None,
            country=country if confidence >= 0.3 else None,
            motive=motive if confidence >= 0.3 else None,
            confidence=confidence,
            attribution_method=self._get_attribution_method(
                bool(source_ip), bool(pattern), actor_type != "unknown"
            ),
        )
        
        self._attribution_history.append(attribution)
        return attribution

    def _infer_actor_from_pattern(self, action: dict) -> tuple[str, float]:
        """
        从行为模式推断攻击者类型。
        
        Returns:
            (actor_type, confidence)
        """
        pattern = action.get("pattern") or ""
        action_type = action.get("action_type", "")
        risk_score = action.get("risk_score", 0.5)
        
        # 检查各类型匹配
        scores = {}
        
        for actor, info in self.ACTOR_PATTERNS.items():
            score = 0.0
            count = 0
            
            # 模式匹配
            for p in info["patterns"]:
                if p.lower() in pattern.lower():
                    score += 0.3
                count += 1
            
            # 指示器检查（需要更多上下文，这里简化）
            # 实际上应该分析历史行为方差、时间模式等
            
            if count > 0:
                scores[actor] = min(1.0, score / count * 2)
        
        if not scores:
            return "unknown", 0.1
        
        # 返回最高匹配
        best_actor = max(scores, key=scores.get)
        return best_actor, scores[best_actor]

    def _infer_motive_from_context(self, action: dict) -> tuple[str, float]:
        """
        从上下文推断攻击动机。
        
        Returns:
            (motive, confidence)
        """
        action_type = action.get("action_type", "")
        pattern = action.get("pattern") or ""
        target = action.get("target") or ""
        
        scores = {}
        
        for motive, info in self.MOTIVE_PATTERNS.items():
            score = 0.0
            
            # 动作类型匹配
            if action_type in info["actions"]:
                score += 0.4
            
            # 指示器匹配
            for indicator in info["indicators"]:
                if indicator.lower() in pattern.lower() or indicator.lower() in target.lower():
                    score += 0.2
            
            scores[motive] = min(1.0, score)
        
        if not scores or max(scores.values()) < 0.2:
            return "unknown", 0.1
        
        best_motive = max(scores, key=scores.get)
        return best_motive, scores[best_motive]

    def _infer_country_from_ip(self, ip: Optional[str]) -> Optional[str]:
        """从 IP 推断大致地区（非常不准确！）"""
        if not ip:
            return None
        
        # 简化实现：实际上应该用 GeoIP 库
        # 这里仅作为占位符
        return None

    def _compute_confidence(
        self,
        actor_conf: float,
        motive_conf: float,
        has_ip: bool,
        has_pattern: bool,
    ) -> float:
        """
        综合计算归因置信度。
        """
        confidence = 0.0
        
        if has_ip:
            confidence += 0.2
        if has_pattern:
            confidence += 0.3
        
        confidence += actor_conf * 0.25
        confidence += motive_conf * 0.25
        
        return min(1.0, confidence)

    def _get_attribution_method(
        self, has_ip: bool, has_pattern: bool, actor_inferred: bool
    ) -> str:
        """确定归因方法"""
        if has_ip and has_pattern:
            return "ip_pattern_correlation"
        elif has_pattern and actor_inferred:
            return "behavioral_analysis"
        elif has_ip:
            return "ip_geolocation"
        else:
            return "pattern_match"

    def get_threat_intel_summary(self) -> dict:
        """
        获取威胁情报摘要。
        
        Returns:
            包含归因统计的字典
        """
        if not self._attribution_history:
            return {
                "total_attributed": 0,
                "actor_distribution": {},
                "motive_distribution": {},
                "avg_confidence": 0.0,
            }
        
        actor_counts = defaultdict(int)
        motive_counts = defaultdict(int)
        total_confidence = 0.0
        
        for attr in self._attribution_history:
            if attr.actor_type:
                actor_counts[attr.actor_type] += 1
            if attr.motive:
                motive_counts[attr.motive] += 1
            total_confidence += attr.confidence
        
        return {
            "total_attributed": len(self._attribution_history),
            "actor_distribution": dict(actor_counts),
            "motive_distribution": dict(motive_counts),
            "avg_confidence": total_confidence / len(self._attribution_history),
            "high_confidence_count": sum(1 for a in self._attribution_history if a.confidence >= 0.5),
        }
