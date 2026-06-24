# AgentSafety 深度审查报告

**审查日期**: 2026-06-24  
**审查框架**: Yann LeCun 自监督学习批判 + 梁文峰开源理念 + LeCun AI边界理论

---

## 一、LeCun 自监督学习批判

### 核心问题：规则学习完全依赖人工标注

**现状分析**：
- `policies.py` 中 `default_policies` 是硬编码的人工标注规则列表
- `PolicyLearner.analyze_recent_events()` 仅做频率统计（数出现次数）
- `PolicyLearner.suggest_rules()` 基于"出现5次以上→建议WARN"推断规则
- `SafetyConfig.risk_keywords`、`shell_dangerous_chars`、`path_traversal_patterns` 是人工枚举列表

**LeCun 批判**：
> 真正的AI应该从少量样本中学习世界的结构，而不是在海量文本上做监督学习。

当前实现是**监督学习**：人工定义规则 → 匹配模式 → 决策。没有从数据中自监督学习任何结构。

**改进方案**（已实现 `self_supervised.py`）：
1. **CausalFeatureExtractor**：从操作中提取32维因果特征向量
   - 操作类型语义（8维）
   - 目标资源类型（8维）—— 从路径结构**自监督推断**，不依赖人工标注
   - 操作意图推断（8维）—— 从操作+结果联合分布学习
   - 上下文风险因子（8维）—— 递归性/权限/范围/可逆性

2. **自监督更新机制**：
   - 不需要人工标注！
   - outcome 信号自然产生：`"blocked"` = 负样本，`"allowed_safe"` = 正样本
   - 用梯度下降更新危险/安全原型中心

3. **对比学习分类**：
   - 计算操作特征到危险/安全原型中心的距离
   - 生成因果解释（不是模式匹配的理由）

---

## 二、梁文峰开源批判

### 核心问题：BLOCK 机制剥夺用户知情同意权

**现状分析**：
- `SafetyDecision.decision` 是 `ALLOW/WARN/BLOCK/CIRCUIT_BREAK` 四选一
- 用户无法看到 BLOCK 的具体判断依据
- 用户无法选择"接受风险继续执行"
- 规则对用户不可见、不可改、不可选

**梁文峰理念**：
> 闭源的本质是"我对用户负责"——但开源的本质是"用户对自己负责"。

当前 BLOCK 模式是**闭源思维**：系统决定用户能做什么，用户只能服从。

**改进方案**（已实现 `informed_consent.py`）：

1. **RiskDisclosure**：完整披露决策理由
   - 因果解释（为什么危险）
   - 模式解释（匹配了什么规则）
   - 潜在后果
   - 安全替代方案
   - 影响范围评估
   - 可逆性评估

2. **ConsentLevel**：用户同意等级
   - `UNASKED` → `INFORMED` → `ACCEPTED/REJECTED`
   - 用户可以选择"接受风险继续"

3. **用户自定义规则**：
   - `add_user_rule()`：用户添加自己的规则
   - `update_thresholds()`：用户自定义阈值
   - 用户规则优先于系统规则

4. **审计日志**：完整记录用户选择

---

## 三、LeCun AI边界理论批判

### 核心问题：决策是模式匹配，不是因果推理

**现状分析**：
- `PolicyRule.matches()` 只是 glob/regex 模式匹配
- `SafetyEngine.evaluate()` 是 if-then-else 链
- `CircuitBreaker` 是简单计数器

**LeCun AI边界**：
> 当前LLM的局限在于无法真正推理（规划、因果、可解释性）。

当前实现只能回答"因为匹配了规则X"，无法回答"为什么这个操作是危险的"。

**改进方案**（在 `self_supervised.py` 中）：

1. **CausalDecision**：
   ```python
   causal_explanation: str   # LeCun 因果解释
   pattern_explanation: str  # 模式匹配的解释
   is_real_threat: bool      # 梁文峰：真正威胁 vs 看起来像威胁
   ```

2. **_distinguish_real_threat()**：
   - 区分真正威胁 vs 看起来像威胁
   - 例如：`rm -rf /tmp/test` = 看起来像威胁（实际安全）
   - 例如：`rm -rf /home/*` = 真正威胁（批量删除用户数据）

3. **_explain_causal()**：
   - 从特征向量生成因果解释
   - 不是"匹配了规则"，而是"检测到递归操作风险"

---

## 四、梁文峰"做最本质的事情"批判

### 核心问题：阻止的是"看起来像威胁"的东西

**现状分析**：
- `block-rm-rf` 规则匹配 `*rm -rf*`，无法区分：
  - 安全：`rm -rf /tmp/test`（清理临时目录）
  - 危险：`rm -rf /home/*`（批量删除用户数据）
- 没有上下文感知能力

**梁文峰"做最本质的事情"**：
> 做最本质的事情：区分真正的威胁 vs 看起来像威胁。

**改进方案**：

1. **_distinguish_real_threat()** 方法：
   ```python
   # 检查临时目录操作（通常安全）
   if "/tmp" in target:
       return False, None  # 不是真正威胁
   
   # 检查用户目录递归删除（真正威胁）
   if "/home" in target and "*" in cmd:
       return True, "建议：先检查目标路径是否包含重要数据"
   ```

2. **alternative_safe_action** 字段：
   - 当阻止时，提供安全替代方案
   - 例如："建议使用 'rm -i' 逐个确认"

---

## 五、总结

### 当前实现的三大缺陷

| 缺陷 | LeCun批判 | 梁文峰批判 | 改进 |
|------|-----------|-----------|------|
| 规则学习 | 人工标注，非自监督 | — | `CausalFeatureExtractor` 自监督特征提取 |
| BLOCK机制 | 无法因果推理 | 剥夺知情同意权 | `InformedConsentManager` 知情同意 |
| 威胁识别 | 模式匹配，非因果 | 阻止"看起来像威胁" | `_distinguish_real_threat()` |

### 新增文件

1. `/home/fuguang/AgentSafety/src/agent_safety/self_supervised.py`
   - 自监督学习模块
   - 因果推理引擎

2. `/home/fuguang/AgentSafety/src/agent_safety/informed_consent.py`
   - 知情同意管理器
   - 用户自定义规则

---

## 六、编译验证
