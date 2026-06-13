"""
AgentSafety 内置策略规则
"""

from .core import PolicyRule, ActionType, RiskLevel

# 默认策略：最小权限 + 高风险拦截
default_policies: list[dict] = [
    # === 关键文件保护 ===
    {
        "rule_id": "block-ssh-keys",
        "name": "禁止操作 SSH 私钥",
        "action_type": ActionType.FILE_READ,
        "target_pattern": "*/.ssh/*",
        "risk_level": RiskLevel.CRITICAL,
        "decision": "BLOCK",
        "reason": "SSH 私钥属于高敏感凭据",
    },
    {
        "rule_id": "block-etc-passwd",
        "name": "禁止修改系统账号",
        "action_type": ActionType.FILE_WRITE,
        "target_pattern": "*/etc/passwd",
        "risk_level": RiskLevel.CRITICAL,
        "decision": "BLOCK",
        "reason": "/etc/passwd 是系统账号文件，修改会导致系统无法登录",
    },
    {
        "rule_id": "block-etc-shadow",
        "name": "禁止修改密码文件",
        "action_type": ActionType.FILE_WRITE,
        "target_pattern": "*/etc/shadow",
        "risk_level": RiskLevel.CRITICAL,
        "decision": "BLOCK",
        "reason": "/etc/shadow 存储密码哈希",
    },
    # === 危险 shell 操作 ===
    {
        "rule_id": "block-rm-rf",
        "name": "警告递归删除",
        "action_type": ActionType.SHELL_EXECUTE,
        "target_pattern": "*rm -rf*",
        "risk_level": RiskLevel.HIGH,
        "decision": "WARN",
        "reason": "递归删除可能导致数据永久丢失",
    },
    {
        "rule_id": "block-chmod-777",
        "name": "警告全开权限",
        "action_type": ActionType.SHELL_EXECUTE,
        "target_pattern": "*chmod 777*",
        "risk_level": RiskLevel.HIGH,
        "decision": "WARN",
        "reason": "chmod 777 违反最小权限原则",
    },
    # === 网络安全 ===
    {
        "rule_id": "block-exec-js",
        "name": "禁止执行外部 JS",
        "action_type": ActionType.SHELL_EXECUTE,
        "target_pattern": "*node*eval*",
        "risk_level": RiskLevel.HIGH,
        "decision": "WARN",
        "reason": "动态执行外部 JS 代码有代码注入风险",
    },
    {
        "rule_id": "block-curl-pipe-sh",
        "name": "禁止 pipe curl 到 shell",
        "action_type": ActionType.SHELL_EXECUTE,
        "target_pattern": "*curl*|*sh",
        "risk_level": RiskLevel.CRITICAL,
        "decision": "BLOCK",
        "reason": "curl|sh 是最常见的远程代码执行攻击向量",
    },
    # === 环境变量 ===
    {
        "rule_id": "warn-env-keys",
        "name": "警告读取密钥类环境变量",
        "action_type": ActionType.ENV_READ,
        "target_pattern": "*KEY*",
        "risk_level": RiskLevel.HIGH,
        "decision": "WARN",
        "reason": "读取密钥类环境变量可能泄露敏感信息",
    },
    {
        "rule_id": "block-env-secret-write",
        "name": "禁止写入密钥环境变量",
        "action_type": ActionType.ENV_WRITE,
        "target_pattern": "*SECRET*",
        "risk_level": RiskLevel.CRITICAL,
        "decision": "BLOCK",
        "reason": "禁止修改密钥类环境变量",
    },
    # === Agent 协作安全 ===
    {
        "rule_id": "warn-agent-spawn",
        "name": "警告 Spawn 新 Agent",
        "action_type": ActionType.AGENT_SPAWN,
        "target_pattern": None,
        "risk_level": RiskLevel.MEDIUM,
        "decision": "WARN",
        "reason": "Spawn 新 Agent 会增加攻击面",
    },
    {
        "rule_id": "warn-agent-cross-team",
        "name": "警告跨团队通信",
        "action_type": ActionType.AGENT_MESSAGE,
        "target_pattern": "*other-team*",
        "risk_level": RiskLevel.MEDIUM,
        "decision": "WARN",
        "reason": "跨团队消息需要验证接收方身份",
    },
    # === 数据导出 ===
    {
        "rule_id": "warn-data-export",
        "name": "警告批量数据导出",
        "action_type": ActionType.DATA_EXPORT,
        "target_pattern": "*",
        "risk_level": RiskLevel.MEDIUM,
        "decision": "WARN",
        "reason": "批量数据导出可能违反数据最小化原则",
    },
    {
        "rule_id": "block-data-delete-production",
        "name": "禁止删除生产数据",
        "action_type": ActionType.DATA_DELETE,
        "target_pattern": "*production*",
        "risk_level": RiskLevel.CRITICAL,
        "decision": "BLOCK",
        "reason": "生产环境数据删除需经过审批流程",
    },
]


# === V 6/13 21:46 新增规则 (针对根系统路径的删除) ===
# 设计: rm -rf / 这种命令应该 CRITICAL + BLOCK, 不只是 WARN
# 直接合并到 default_policies 末尾, 不需要修改 PolicyStore
default_policies.extend([
    {
        "rule_id": "block-rm-system-path",
        "name": "禁止删除系统关键路径",
        "action_type": ActionType.SHELL_EXECUTE,
        "target_pattern": "rm -rf /*",
        "risk_level": RiskLevel.CRITICAL,
        "decision": "BLOCK",
        "reason": "删除系统根路径会导致系统不可用, 必须 BLOCK",
    },
    {
        "rule_id": "block-rm-home",
        "name": "禁止递归删除 home",
        "action_type": ActionType.SHELL_EXECUTE,
        "target_pattern": "rm -rf /home*",
        "risk_level": RiskLevel.CRITICAL,
        "decision": "BLOCK",
        "reason": "递归删除 home 目录会导致用户数据永久丢失",
    },
    {
        "rule_id": "block-write-system-bin",
        "name": "禁止写入系统 bin",
        "action_type": ActionType.FILE_WRITE,
        "target_pattern": "*/bin/*",
        "risk_level": RiskLevel.CRITICAL,
        "decision": "BLOCK",
        "reason": "系统 bin 目录写入会破坏系统完整性",
    },
])


class PolicyStore:
    """策略存储与查询"""

    def __init__(self, policies: list[dict] | None = None):
        from .core import PolicyRule
        self._rules: list[PolicyRule] = [
            PolicyRule(**p) for p in (policies or default_policies)
        ]

    def list_rules(self) -> list[PolicyRule]:
        return self._rules

    def get_rule(self, rule_id: str) -> PolicyRule | None:
        for r in self._rules:
            if r.rule_id == rule_id:
                return r
        return None

    def add_rule(self, rule: PolicyRule):
        self._rules.append(rule)

    def remove_rule(self, rule_id: str):
        self._rules = [r for r in self._rules if r.rule_id != rule_id]


# === V 6/13 21:46 新增规则 (针对根系统路径的删除) ===
# 设计: rm / 这种命令应该 CRITICAL + BLOCK, 不只是 WARN
extended_policies: list[dict] = [
    {
        "rule_id": "block-rm-system-path",
        "name": "禁止删除系统关键路径",
        "action_type": ActionType.SHELL_EXECUTE,
        "target_pattern": "*rm -rf /*|rm -rf /|rm -rf /etc|rm -rf /usr|rm -rf /var|rm -rf /boot|rm -rf /bin|rm -rf /sbin",
        "risk_level": RiskLevel.CRITICAL,
        "decision": "BLOCK",
        "reason": "删除系统关键路径会导致系统不可用，必须 BLOCK",
    },
    {
        "rule_id": "block-rm-home",
        "name": "警告递归删除 home",
        "action_type": ActionType.SHELL_EXECUTE,
        "target_pattern": "*rm -rf ~*|rm -rf /home*|rm -rf ~/*",
        "risk_level": RiskLevel.CRITICAL,
        "decision": "BLOCK",
        "reason": "递归删除 home 目录会导致用户数据永久丢失",
    },
    {
        "rule_id": "block-write-system-bin",
        "name": "禁止写入系统 bin",
        "action_type": ActionType.FILE_WRITE,
        "target_pattern": "*/bin/*|*/sbin/*|*/usr/bin/*|*/usr/sbin/*",
        "risk_level": RiskLevel.CRITICAL,
        "decision": "BLOCK",
        "reason": "系统 bin 目录写入会破坏系统完整性",
    },
]
