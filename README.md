# FCM Hosts Next

自动维护 Google Firebase Cloud Messaging (FCM) 优选 Hosts。项目在中国大陆双栈机器上直接采集、实测、发布，目标是给 Android / microG / Google Play services 提供更稳定的 FCM 长连接入口。

## 架构

当前生产架构是单机流水线：

1. **Harvest**：通过阿里 / DNSPod 等能透传 ECS 的解析器，用国内、台湾和海外子网查询 `mtalk` 与 `alt{1,3,5,7}-mtalk`，采集全球 PoP 的候选 IPv4/IPv6。离 bj-edge 最近的未必在亚洲（v6 美西 PoP 约 210ms，亚洲约 330ms），交给 TCP 实测决定。
2. **Seed**：读取仓库内上一轮成功的 `fcm_*.hosts`，把历史可用 IP 继续作为种子。
3. **Verify**：在大陆双栈机器（bj-edge）上对候选 IP 执行一次 TCP `5228` 握手粗测。FCM 只在各 PoP 的 `.188` / `::bc` 上监听，不做邻近扩展。
4. **Refine**：粗测最快的 40 个 IP 各间隔握手 20 次，按“中位 RTT + 丢包率 × 1s（SYN 重传代价）”评分；丢包过半的淘汰。只看 TCP，不看 ICMP：晚高峰出境链路的 ICMP 丢包对所有 Google IP 都差不多，分不出好坏。
5. **Pick**：每个协议族按评分选 12 个，每个 /24（IPv6 为 /64）只取一个，保证每个 FCM 域名各占一个独立 IP。
6. **Publish**：生成并提交 `fcm_ipv4.hosts`、`fcm_ipv6.hosts`、`fcm_dual.hosts`，文件头记录每个 IP 的中位延迟、p90 和丢包。

核心实现是 Go 单二进制，无 Python runtime、无 pip 依赖、无跨 runner artifact 搬运。

## 产物

- [fcm_dual.hosts](fcm_dual.hosts)：推荐。双栈输出；若某次只选出单栈，会自动降级。
- [fcm_ipv6.hosts](fcm_ipv6.hosts)：纯 IPv6 输出。
- [fcm_ipv4.hosts](fcm_ipv4.hosts)：纯 IPv4 输出。

默认每天更新 4 次（bj-edge 上的 `fcm-hosts-next.timer`）；临时刷新：`ssh bj-edge sudo systemctl start fcm-hosts-next.service`。

## 使用

服务器分发地址：

```text
https://fcm-hosts.cagedbird.cn/fcm_dual.hosts
```

可用于：

- 系统 hosts 定时拉取并原子覆盖。
- sing-box / Clash 的 hosts 数据源。

## 本地运行

```bash
go test ./...
go run ./cmd/fcmhost run -workdir .
```

常用调试：

```bash
go run ./cmd/fcmhost run -workdir . -dns=false -v
```

`-dns=false` 只使用现有 hosts/raw seeds 做验证，适合快速确认当前网络能否连通 FCM `5228`。

---

_Status: Automated / Mainland dual-stack verified_

## Agent-native Skills

### Start here

- 自动化运行 / 服务器发布 / 本地验证 -> [.agents/skills/runner-publish/SKILL.md](.agents/skills/runner-publish/SKILL.md)

### Skills

- [.agents/skills/runner-publish/SKILL.md](.agents/skills/runner-publish/SKILL.md): 管理 bj-edge 上的 FCM hosts 定时流水线、推送用 deploy key 与本地运行验证。Trigger: 修改 `scripts/publish.sh` 或 `deploy/`、排查 hosts 刷新/发布故障或验证业务代码。

### Deep docs

- [README.md](README.md): 架构、产物列表与基本用法

### Do not read everything

Agent 应该首先读取 [AGENTS.md](AGENTS.md) 了解项目级硬规则与定位，随后根据任务选择读取对应的 skill 或文档，禁止无序扫描整个仓库。
