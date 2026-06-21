# fcm-hosts-next 维护指南

> 💡 关于本项目的 Agent-native Skills 与任务路由，请先阅读 [README.md](README.md#agent-native-skills)。

这个仓库生成并发布 Google Firebase Cloud Messaging (FCM) 优选 hosts，给 Android / microG / Google Play services 使用。生产流水线跑在中国大陆双栈 self-hosted runner 上。

## 生产链路

- Runner label：`self-hosted`, `Linux`, `X64`, `tencent-fcm`, `china-dualstack`
- Workflow：`.github/workflows/main.yml`
- 调度：每天 4 次，UTC `01:17`, `07:17`, `13:17`, `19:17`
- 生成：`go run ./cmd/fcmhost run -workdir .`
- 发布文件：
  - `fcm_ipv4.hosts`
  - `fcm_ipv6.hosts`
  - `fcm_dual.hosts`
- 分发路径：`/srv/cagedbird/fcm-hosts-next/`
- 公网推荐地址：`https://fcm-hosts.cagedbird.cn/fcm_dual.hosts`
- 兼容旧地址：`https://cagedbird.cn/fcm-hosts-next/fcm_dual.hosts`

## 硬规则

- **不走 HTTPS 提交:** Checkout 与 push 必须使用 SSH deploy key (`ACTIONS_DEPLOY_KEY`)，不能用 `GITHUB_TOKEN` 的 HTTPS 地址，以防大陆网络下 HTTPS 连接 GitHub 443 超时。
- **防止自循环:** 自动生成的 hosts 提交必须带 `[skip ci]` 标签，且 workflow 触发条件需排除 bot push 避免无限循环。
- **不直接修改生产环境:** 禁止在服务器上直接 `sed` 或编辑发布文件。任何更改必须本地生成并测试通过，再由 scp/workflow 部署。
