#!/usr/bin/env bash
# 生产流水线：由 bj-edge 的 fcm-hosts-next.timer 以 fcm-runner 用户运行（见 deploy/）。
# 拉取 main → 测试 → 采集实测 → 发布到本机 Caddy 目录 → 提交并推送 hosts。
set -euo pipefail

repo_dir="${FCM_REPO_DIR:-/var/lib/fcm-runner/fcm-hosts-next}"
publish_dir="${FCM_PUBLISH_DIR:-/srv/cagedbird/fcm-hosts-next}"
hosts_files=(fcm_ipv4.hosts fcm_ipv6.hosts fcm_dual.hosts)
bot_name="fcm-hosts-next[bj-edge]"
bot_email="fcm-runner@cagedbird.cn"

cd "$repo_dir"

# 上一轮没推送成功的本地提交直接丢弃，以远端为准重新生成。
git fetch --quiet origin main
git reset --quiet --hard origin/main
git clean --quiet -fdx

go test ./...
go run ./cmd/fcmhost run -workdir .

unexpected_paths="$(git status --porcelain --untracked-files=all | awk '{print $2}' | grep -vE '^fcm_(ipv4|ipv6|dual)\.hosts$' || true)"
if [ -n "$unexpected_paths" ]; then
  echo "Unexpected changed files detected:" >&2
  printf '%s\n' "$unexpected_paths" >&2
  exit 1
fi

# 逐个原子替换，客户端不会读到写了一半的文件。
for file in "${hosts_files[@]}"; do
  install -m 0644 "$file" "$publish_dir/.$file.new"
  mv -f "$publish_dir/.$file.new" "$publish_dir/$file"
done
sed -n '1,12p' "$publish_dir/fcm_dual.hosts"

git add "${hosts_files[@]}"
if git diff --cached --quiet; then
  echo "No changes, skipping commit"
  exit 0
fi

commit_msg="Update FCM hosts - $(date -u +'%Y-%m-%d %H:%M UTC') [skip ci]"
# 连续的自动提交合并成一个，避免每天 4 个提交刷屏。
if [ "$(git log -1 --format='%an')" = "$bot_name" ]; then
  git -c user.name="$bot_name" -c user.email="$bot_email" commit --quiet --amend --reset-author -m "$commit_msg"
  git push --quiet --force-with-lease origin main
else
  git -c user.name="$bot_name" -c user.email="$bot_email" commit --quiet -m "$commit_msg"
  git push --quiet origin main
fi
echo "Published and pushed: $commit_msg"
