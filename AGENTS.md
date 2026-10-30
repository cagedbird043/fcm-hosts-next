# fcm-hosts-next 维护指南

> 💡 关于本项目的 Agent-native Skills 与任务路由，请先阅读 [README.md](README.md#agent-native-skills)。

这个仓库生成并发布 Google Firebase Cloud Messaging (FCM) 优选 hosts，给 Android / microG / Google Play services 使用。生产流水线是 bj-edge（腾讯云北京，大陆双栈）上的 systemd 定时任务，全程在国内完成。

## 生产链路

- 运行：bj-edge 的 `fcm-hosts-next.timer` → `fcm-hosts-next.service`（`deploy/` 下两个文件，装在 `/etc/systemd/system/`），以 `fcm-runner` 用户执行 `scripts/publish.sh`
- 工作副本：`/var/lib/fcm-runner/fcm-hosts-next`（每轮先 `reset --hard origin/main`）
- 调度：每天 4 次，UTC `01:17`, `07:17`, `13:17`, `19:17`
- 生成：`go run ./cmd/fcmhost run -workdir .`
- 发布文件：
  - `fcm_ipv4.hosts`
  - `fcm_ipv6.hosts`
  - `fcm_dual.hosts`
- 分发路径：bj-edge 本机 `/srv/cagedbird/fcm-hosts-next/`，Caddy 站点 `fcm-hosts.cagedbird.cn`
- 公网地址：`https://fcm-hosts.cagedbird.cn/fcm_dual.hosts`
- GitHub Actions：`.github/workflows/main.yml` 只在代码改动时跑 `go test` 和 `shellcheck`，不采集、不发布

## 硬规则

- **推送走 SSH 443:** `fcm-runner` 用 repo deploy key `fcm-runner@bj-edge`（可写）推送，`~/.ssh/config` 把 `github.com` 指到 `ssh.github.com:443`，不用 HTTPS token。
- **防止自循环:** 自动生成的 hosts 提交必须带 `[skip ci]` 标签。
- **不直接修改生产环境:** 禁止在服务器上直接 `sed` 或编辑发布文件。任何更改必须提交到仓库，由下一轮 `scripts/publish.sh` 生成和发布；`deploy/` 下的 unit 改动需要手动复制到 `/etc/systemd/system/` 并 `daemon-reload`。
