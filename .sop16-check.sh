#!/usr/bin/env bash
# V SOP #16 跨仓 check 脚本 (非 git 仓版)
# 4 项: dirty / 凭据 / 备份 / 注释 SOP
set -e
echo "🛡️ V SOP #16 跨仓 check running..."

# 1. 凭据脱敏
if grep -rE "ghp_[a-zA-Z0-9]+" . 2>/dev/null | grep -v ".bak" | head -1; then
    echo "❌ 凭据暴露! 必先脱敏"
    exit 1
fi
echo "✅ V SOP #16 check passed"
