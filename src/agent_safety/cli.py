"""
AgentSafety CLI - 命令行入口
"""

import sys
import json
import argparse
from .core import SafetyEngine, SafetyAction, ActionType, RiskLevel

def main():
    parser = argparse.ArgumentParser(description="AgentSafety CLI")
    sub = parser.add_subparsers(dest="cmd")

    # 安全评估
    eval_p = sub.add_parser("eval", help="评估一个 Action")
    eval_p.add_argument("--type", required=True, help="ActionType，如 shell_execute, file_write")
    eval_p.add_argument("--agent", required=True, help="Agent ID")
    eval_p.add_argument("--target", default="", help="操作目标")
    eval_p.add_argument("--tool", default="", help="工具名")
    eval_p.add_argument("--details", default="{}", help="额外参数 JSON")
    eval_p.add_argument("--dry-run", action="store_true", help="试运行")
    eval_p.add_argument("--json", action="store_true", help="JSON 输出")

    # 列出规则
    list_p = sub.add_parser("list-rules", help="列出所有策略规则")
    list_p.add_argument("--json", action="store_true", help="JSON 输出")

    # 统计
    stat_p = sub.add_parser("stats", help="显示安全统计")
    stat_p.add_argument("--json", action="store_true", help="JSON 输出")

    args = parser.parse_args()

    engine = SafetyEngine()

    if args.cmd == "eval":
        try:
            action_type = ActionType(args.type)
        except ValueError:
            action_type = ActionType.UNKNOWN

        try:
            details = json.loads(args.details)
        except json.JSONDecodeError:
            details = {}

        action = SafetyAction(
            action_id=f"cli-{id(object()):x}",
            action_type=action_type,
            agent_id=args.agent,
            target=args.target or None,
            tool_name=args.tool or None,
            details=details,
            dry_run=args.dry_run,
        )
        decision = engine.evaluate(action)

        if args.json:
            print(json.dumps({
                "action_id": decision.action_id,
                "risk_level": decision.risk_level.name,
                "decision": decision.decision,
                "reason": decision.reason,
                "risk_score": decision.risk_score,
                "matched_policies": decision.matched_policies,
            }, ensure_ascii=False, indent=2))
        else:
            print(f"[{decision.risk_level}] {decision.decision}: {decision.reason}")
            if decision.matched_policies:
                print(f"  匹配规则: {', '.join(decision.matched_policies)}")
            print(f"  风险评分: {decision.risk_score:.2f}")

    elif args.cmd == "list-rules":
        rules = engine._rules
        if args.json:
            print(json.dumps([{
                "rule_id": r.rule_id,
                "name": r.name,
                "action_type": r.action_type.value if r.action_type else None,
                "target_pattern": r.target_pattern,
                "risk_level": r.risk_level.name,
                "decision": r.decision,
                "enabled": r.enabled,
            } for r in rules], ensure_ascii=False, indent=2))
        else:
            for r in rules:
                status = "✓" if r.enabled else "✗"
                print(f"  [{status}] {r.rule_id}: {r.name} ({r.risk_level}, {r.decision})")

    elif args.cmd == "stats":
        stats = engine.get_stats()
        if args.json:
            print(json.dumps(stats, indent=2))
        else:
            print(f"总规则数: {stats['total_rules']}")
            print(f"熔断器状态: {'OPEN' if stats['circuit_breaker_open'] else 'CLOSED'}")
            print(f"窗口内风险事件: {stats['risk_events_in_window']}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
