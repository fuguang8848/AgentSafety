"""
Self-Supervised Learning Module for AgentSafety

基于 LeCun 自监督学习理念的改进：
1. 从少量样本中学习世界结构（不是海量标注数据）
2. 学习操作之间的因果关系（不是表面模式）
3. 用对比学习区分危险 vs 安全操作的本质特征

梁文峰"做最本质的事情"：
- 阻止真正的威胁（因果），不是看起来像威胁（模式）
"""

from __future__ import annotations

import time
import hashlib
import logging
from typing import Optional
from dataclasses import dataclass, field
from collections import defaultdict
import numpy as np

logger = logging.getLogger(__name__)


# ── 简化的自监督特征提取器 ────────────────────────────────────────────────


class CausalFeatureExtractor:
    """
    从操作中提取因果特征，不是表面模式。
    
    LeCun 自监督学习核心：从少量样本学习世界的结构。
    这里我们学习"危险操作的因果链"，而不是"危险模式的列表"。
    """
    
    def __init__(self):
        # 因果特征向量维度
        self._feature_dim = 32
        
        # 学习到的原型（聚类中心）
        self._safe_prototypes: list[np.ndarray] = []
        self._dangerous_prototypes: list[np.ndarray] = []
        
        # 观测统计（用于自监督信号）
        self._observation_count = 0
        self._dangerous_observations = 0
        
    def extract(self, action_type: str, target: str, details: dict) -> np.ndarray:
        """
        提取操作的因果特征向量。
        
        特征维度 32:
        - 8: 操作类型语义（file/shell/env/network/data/agent）
        - 8: 目标资源类型（path/credential/data/system/config）
        - 8: 操作意图推断（create/read/modify/delete/spawn/transfer）
        - 8: 上下文风险因子（权限/位置/范围/可逆性）
        """
        features = np.zeros(self._feature_dim, dtype=np.float32)
        
        # 特征1: 操作类型语义
        op_semantic = self._encode_operation_type(action_type)
        features[:8] = op_semantic
        
        # 特征2: 目标资源类型
        target_semantic = self._encode_target_type(target, details)
        features[8:16] = target_semantic
        
        # 特征3: 操作意图推断（自监督：无标签，从结构推断）
        intent = self._infer_intent(action_type, target, details)
        features[16:24] = intent
        
        # 特征4: 上下文风险因子
        risk_factors = self._encode_risk_context(target, details)
        features[24:32] = risk_factors
        
        return features
    
    def _encode_operation_type(self, action_type: str) -> np.ndarray:
        """编码操作类型语义"""
        vec = np.zeros(8, dtype=np.float32)
        type_map = {
            "file": (0, 1, 0, 0, 0, 0, 0, 0),
            "shell": (0, 0, 1, 0, 0, 0, 0, 0),
            "env": (0, 0, 0, 1, 0, 0, 0, 0),
            "network": (0, 0, 0, 0, 1, 0, 0, 0),
            "data": (0, 0, 0, 0, 0, 1, 0, 0),
            "agent": (0, 0, 0, 0, 0, 0, 1, 0),
            "dns": (0, 0, 0, 0, 0, 0, 0, 1),
        }
        key = action_type.split("_")[0] if "_" in action_type else action_type
        if key in type_map:
            vec[:] = type_map[key]
        return vec
    
    def _encode_target_type(self, target: str, details: dict) -> np.ndarray:
        """编码目标资源类型（从路径/内容结构推断，不是人工标注）"""
        vec = np.zeros(8, dtype=np.float32)
        if not target:
            return vec
            
        target_lower = target.lower()
        
        # 自监督信号：从路径结构推断资源类型（无人工标注）
        if any(x in target_lower for x in [".ssh", "id_rsa", "id_ed25519", ".pem"]):
            vec[0] = 1.0  # credential
        elif any(x in target_lower for x in ["/etc/passwd", "/etc/shadow", "/etc/group"]):
            vec[1] = 1.0  # system_config
        elif any(x in target_lower for x in ["/bin", "/sbin", "/usr/bin", "/usr/sbin"]):
            vec[2] = 1.0  # system_binary
        elif any(x in target_lower for x in ["/home", "/root", "/Users"]):
            vec[3] = 1.0  # user_data
        elif any(x in target_lower for x in ["database", "db", ".db", ".sqlite"]):
            vec[4] = 1.0  # data_store
        elif any(x in target_lower for x in ["secret", "key", "token", "password"]):
            vec[5] = 1.0  # sensitive
        elif any(x in target_lower for x in ["/tmp", "/var/tmp", "/cache"]):
            vec[6] = 1.0  # temporary
        else:
            vec[7] = 1.0  # other
            
        return vec
    
    def _infer_intent(self, action_type: str, target: str, details: dict) -> np.ndarray:
        """
        推断操作意图（自监督：从操作和结果的联合分布学习）
        
        关键：不是检测"rm -rf"这种模式
        而是理解"删除大量用户数据"这个意图
        """
        vec = np.zeros(8, dtype=np.float32)
        
        # 从 action_type 推断
        if "delete" in action_type.lower():
            vec[0] = 0.9
            # 自监督：检查是否在删除用户数据（高风险）
            if target and "/home" in target.lower():
                vec[0] = 1.0  # 确认删除用户数据
                vec[3] = 0.8  # 不可逆标志
        elif "write" in action_type.lower() or "execute" in action_type.lower():
            vec[1] = 0.8  # modify/create
            # 检查是否写入系统目录（高风险）
            if target and ("/bin" in target.lower() or "/sbin" in target.lower()):
                vec[1] = 1.0
                vec[2] = 0.7  # 系统完整性风险
        elif "read" in action_type.lower():
            vec[2] = 0.6  # read operation
            # 检查是否读取敏感凭证
            if target and (".ssh" in target.lower() or "secret" in target.lower()):
                vec[2] = 1.0
                vec[4] = 0.8  # 情报收集风险
        elif "export" in action_type.lower() or "http" in action_type.lower():
            vec[3] = 1.0  # data transfer
        elif "spawn" in action_type.lower():
            vec[4] = 0.9  # agent spawn
            vec[5] = 0.5  # 权限扩散风险
        elif "env_write" in action_type.lower():
            vec[5] = 1.0  # 环境修改
            
        return vec
    
    def _encode_risk_context(self, target: str, details: dict) -> np.ndarray:
        """编码上下文风险因子"""
        vec = np.zeros(8, dtype=np.float32)
        
        if not target:
            return vec
        
        # 递归风险（自监督：从命令结构学习）
        cmd = details.get("cmd", "") or details.get("command", "") or ""
        if "rm -rf" in cmd or "rm -r" in cmd:
            vec[0] = 0.9  # 递归删除风险
            if "/" in cmd and "*" in cmd:
                vec[0] = 1.0  # 递归通配 = 极高风险
                
        # 权限风险
        if "chmod" in cmd and "777" in cmd:
            vec[1] = 1.0  # 权限开放风险
        elif "chmod" in cmd and "000" in cmd:
            vec[1] = 0.8  # 权限剥夺风险
            
        # 范围风险
        if cmd.startswith("rm -rf /") or cmd.startswith("rm -rf /*"):
            vec[2] = 1.0  # 系统范围
        elif "/home" in target:
            vec[2] = 0.7  # 用户数据范围
        elif "/tmp" in target:
            vec[2] = 0.1  # 临时文件 = 低风险
            
        # 可逆性
        if any(x in cmd for x in ["mv", "cp", "cp -r"]):
            vec[3] = -0.5  # 可逆操作
        elif "rm" in cmd:
            vec[3] = 0.8  # 难以撤销
            
        return vec
    
    def update(self, features: np.ndarray, outcome: str, context: dict):
        """
        自监督更新：用结果信号更新特征表示。
        
        关键：不需要人工标注！
        outcome 是自然产生的信号：
        - "blocked" = 负样本（危险操作）
        - "allowed" + 无事故 = 正样本（安全操作）
        - "allowed" + 出事 = 负样本（误判，需要修正）
        """
        self._observation_count += 1
        
        if outcome == "blocked":
            self._dangerous_observations += 1
            self._update_prototype(features, is_dangerous=True)
        elif outcome == "allowed_safe":
            self._update_prototype(features, is_dangerous=False)
        elif outcome == "allowed_but_harmful":
            # 误判修正：自监督信号告诉我们这是危险的
            self._update_prototype(features, is_dangerous=True)
            logger.warning(f"[SelfSupervised] Correcting false negative: {context}")
    
    def _update_prototype(self, features: np.ndarray, is_dangerous: bool):
        """更新原型中心（简化的在线聚类）"""
        prototypes = self._dangerous_prototypes if is_dangerous else self._safe_prototypes
        
        if len(prototypes) < 10:
            prototypes.append(features)
        else:
            # 移动原型中心（梯度下降简化版）
            alpha = 0.1
            oldest = prototypes[0]
            prototypes[0] = oldest * (1 - alpha) + features * alpha
    
    def classify(self, features: np.ndarray) -> tuple[float, str]:
        """
        用学到的原型进行分类（对比学习）。
        
        Returns:
            (danger_score, reason) - 0-1 危险分数 + 因果解释
        """
        if not self._safe_prototypes or not self._dangerous_prototypes:
            # 冷启动：没有足够观测，返回未知
            return 0.5, "自监督模型尚未学习到足够的样本"
        
        # 计算到各类原型的距离
        safe_dist = min(float(np.linalg.norm(features - p)) for p in self._safe_prototypes)
        dangerous_dist = min(float(np.linalg.norm(features - p)) for p in self._dangerous_prototypes)
        
        # 转换为分数
        total = safe_dist + dangerous_dist + 1e-6
        danger_score = dangerous_dist / total
        
        # 生成因果解释
        reason = self._explain_causal(features, float(danger_score))
        
        return float(danger_score), reason
    
    def _explain_causal(self, features: np.ndarray, score: float) -> str:
        """生成因果解释（不是模式匹配的理由）"""
        explanations = []
        
        # 检查高权重的特征维度
        if features[24] > 0.5:  # 递归风险
            explanations.append("检测到递归操作风险：可能批量删除大量文件")
        if features[25] > 0.5:  # 权限风险
            explanations.append("检测到权限异常：操作可能绕过访问控制")
        if features[26] > 0.5:  # 范围风险
            if features[26] > 0.8:
                explanations.append("检测到系统范围操作：可能影响系统完整性")
            else:
                explanations.append("检测到较广作用范围：影响超出预期")
        if features[27] < -0.3:  # 可逆性
            explanations.append("操作可逆：风险可控")
        elif features[27] > 0.5:  # 不可逆
            explanations.append("操作不可逆：一旦执行无法恢复")
            
        # 意图推断
        if features[20] > 0.8:  # 删除意图
            explanations.append("推断删除意图：可能造成数据永久丢失")
        if features[21] > 0.8:  # 修改意图
            explanations.append("推断修改意图：可能改变系统状态")
        if features[23] > 0.8:  # 数据传输
            explanations.append("推断数据传输意图：可能导致数据外泄")
            
        if not explanations:
            return f"基于自监督学习的风险评估（置信度: {score:.2f}）"
            
        return " | ".join(explanations)


# ── 改进的决策解释器 ──────────────────────────────────────────────────────


@dataclass
class CausalDecision:
    """可解释的因果决策（不是事后诸葛亮）"""
    decision: str              # "ALLOW" | "WARN" | "BLOCK"
    danger_score: float        # 0-1 自监督模型评分
    matched_rules: list[str]   # 匹配的规则（用于审计）
    causal_explanation: str    # LeCun 因果解释
    pattern_explanation: str   # 梁文峰"看起来像威胁"的解释
    is_real_threat: bool       # 梁文峰：真正的威胁 vs 看起来像威胁
    requires_human_review: bool  # 是否需要人工确认
    alternative_safe_action: str | None  # 建议的安全替代操作
    
    def to_dict(self) -> dict:
        return {
            "decision": self.decision,
            "danger_score": self.danger_score,
            "matched_rules": self.matched_rules,
            "causal_explanation": self.causal_explanation,
            "pattern_explanation": self.pattern_explanation,
            "is_real_threat": self.is_real_threat,
            "requires_human_review": self.requires_human_review,
            "alternative_safe_action": self.alternative_safe_action,
        }


class CausalSafetyEngine:
    """
    因果推理安全引擎（改进版）
    
    改进点：
    1. 自监督学习：不是人工标注规则
    2. 因果推理：不是模式匹配
    3. 梁文峰"做本质的事"：区分真正威胁 vs 看起来像威胁
    """
    
    def __init__(self, use_self_supervised: bool = True):
        self._feature_extractor = CausalFeatureExtractor()
        self._use_self_supervised = use_self_supervised
        
        # 经典规则引擎（用于对比和兜底）
        self._rule_based_engine = None  # 延迟初始化
        
        # 决策历史（用于自监督学习）
        self._decision_log: list[dict] = []
        
    def evaluate(
        self, 
        action_type: str, 
        target: str, 
        details: dict,
        dry_run: bool = False
    ) -> CausalDecision:
        """
        评估操作的安全性，返回因果可解释的决策。
        """
        # 1. 提取因果特征
        features = self._feature_extractor.extract(action_type, target, details)
        
        # 2. 自监督分类
        if self._use_self_supervised:
            danger_score, causal_explanation = self._feature_extractor.classify(features)
        else:
            danger_score, causal_explanation = 0.5, "自监督模型未启用"
        
        # 3. 模式匹配（兜底 + 审计）
        pattern_explanation, matched_rules = self._pattern_match(action_type, target, details)
        
        # 4. 梁文峰"做本质的事"：区分真正威胁 vs 看起来像威胁
        is_real_threat, alternative = self._distinguish_real_threat(
            action_type, target, details, danger_score
        )
        
        # 5. 综合决策
        final_score = self._combine_scores(danger_score, matched_rules, is_real_threat)
        decision, requires_review = self._make_decision(final_score, is_real_threat, dry_run)
        
        # 6. 记录决策用于学习
        self._decision_log.append({
            "action_type": action_type,
            "target": target,
            "features": features,
            "danger_score": danger_score,
            "decision": decision,
            "is_real_threat": is_real_threat,
        })
        
        return CausalDecision(
            decision=decision,
            danger_score=danger_score,
            matched_rules=matched_rules,
            causal_explanation=causal_explanation,
            pattern_explanation=pattern_explanation,
            is_real_threat=is_real_threat,
            requires_human_review=requires_review,
            alternative_safe_action=alternative,
        )
    
    def _pattern_match(self, action_type: str, target: str, details: dict) -> tuple[str, list[str]]:
        """经典模式匹配（用于兜底和审计）"""
        matched = []
        reasons = []
        
        cmd = details.get("cmd", "") or details.get("command", "") or ""
        
        # 高风险模式（人工规则，兜底用）
        high_risk_patterns = [
            ("rm -rf /", "block", "系统根目录删除"),
            ("rm -rf /home", "block", "用户数据删除"),
            (".ssh/id_rsa", "warn", "SSH 凭证访问"),
            ("/etc/shadow", "block", "密码文件访问"),
            ("curl | sh", "block", "远程代码执行"),
        ]
        
        for pattern, severity, desc in high_risk_patterns:
            if pattern in cmd or pattern in target:
                matched.append(pattern)
                reasons.append(f"{desc}（模式: {pattern}）")
        
        pattern_explanation = "; ".join(reasons) if reasons else "未匹配高风险模式"
        return pattern_explanation, matched
    
    def _distinguish_real_threat(
        self, 
        action_type: str, 
        target: str, 
        details: dict,
        danger_score: float
    ) -> tuple[bool, str | None]:
        """
        梁文峰"做最本质的事情"：
        区分真正的威胁 vs 看起来像威胁的东西
        
        例如：
        - rm -rf /tmp/test = 看起来像威胁（实际安全）
        - rm -rf /home/* = 真正威胁（批量删除用户数据）
        """
        cmd = details.get("cmd", "") or details.get("command", "") or ""
        
        # 真正威胁的特征：
        # 1. 作用范围是用户数据或系统关键路径
        # 2. 递归操作且目标不确定
        # 3. 操作后数据不可恢复
        
        # 看起来像威胁但实际安全：
        # 1. 作用范围是临时目录
        # 2. 目标明确且有限
        # 3. 操作可逆或有备份
        
        is_real = False
        alternative = None
        
        # 检查临时目录操作（通常安全）
        if "/tmp" in target or "/var/tmp" in target:
            if "rm -rf" in cmd:
                is_real = False
                alternative = None  # 不需要替代，这就是安全的
                return is_real, alternative
        
        # 检查用户目录递归删除（真正威胁）
        if "/home" in target and ("*" in cmd or target.endswith("/home")):
            is_real = True
            alternative = "建议：先检查目标路径是否包含重要数据，或使用 'rm -i' 逐个确认"
            return is_real, alternative
        
        # 检查系统根目录（真正威胁）
        if cmd.startswith("rm -rf /") and len(cmd) < 20:
            is_real = True
            alternative = "建议：如果是清理临时文件，请指定具体路径如 '/tmp/*'"
            return is_real, alternative
        
        # 默认：根据危险分数判断
        if danger_score > 0.8:
            is_real = True
            
        return is_real, alternative
    
    def _combine_scores(
        self, 
        self_supervised_score: float, 
        matched_rules: list[str],
        is_real_threat: bool
    ) -> float:
        """组合自监督分数和规则匹配分数"""
        # 规则匹配提供确定性信号
        rule_weight = min(len(matched_rules) * 0.15, 0.6)
        
        # 如果规则说危险，分数向高推
        if matched_rules:
            # 有匹配规则时，主要信任规则
            combined = max(self_supervised_score, rule_weight)
        else:
            # 没有规则时，用自监督分数
            combined = self_supervised_score
        
        # 真正威胁加权
        if is_real_threat:
            combined = min(combined * 1.2, 1.0)
            
        return combined
    
    def _make_decision(
        self, 
        score: float, 
        is_real_threat: bool,
        dry_run: bool
    ) -> tuple[str, bool]:
        """做出决策"""
        if dry_run:
            # 试运行不阻断
            return "ALLOW", False
            
        if score > 0.9 or (is_real_threat and score > 0.7):
            return "BLOCK", True  # 需要人工审核后解锁
        elif score > 0.6:
            return "WARN", False
        else:
            return "ALLOW", False
    
    def report_outcome(self, action_type: str, target: str, details: dict, outcome: str):
        """
        报告决策结果，用于自监督学习。
        
        outcome: "blocked" | "allowed_safe" | "allowed_but_harmful"
        """
        features = self._feature_extractor.extract(action_type, target, details)
        self._feature_extractor.update(features, outcome, {"target": target})
    
    def get_stats(self) -> dict:
        """获取自监督学习统计"""
        return {
            "total_observations": self._feature_extractor._observation_count,
            "dangerous_observations": self._feature_extractor._dangerous_observations,
            "safe_prototypes_count": len(self._feature_extractor._safe_prototypes),
            "dangerous_prototypes_count": len(self._feature_extractor._dangerous_prototypes),
            "decisions_logged": len(self._decision_log),
        }
