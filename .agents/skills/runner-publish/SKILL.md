---
name: runner-publish
description: Manage the FCM hosts timer pipeline on bj-edge, its GitHub push key, and run local verification
---

## Trigger

- Modifying or validating `scripts/publish.sh`, `deploy/`, or `.github/workflows/main.yml`.
- Troubleshooting FCM hosts generation, publication, or push failures.
- Changing DNS query/validation logic and verifying behavior.

## Entry Point

- Production script: `scripts/publish.sh`
- systemd units: `deploy/fcm-hosts-next.service`, `deploy/fcm-hosts-next.timer`
- Go CLI entry: `go run ./cmd/fcmhost run`
- Generated outputs: `fcm_dual.hosts`, `fcm_ipv4.hosts`, `fcm_ipv6.hosts`

## Workflow

### Local Verification
Before pushing any script or Go CLI updates:
1. Run test suite:
   ```bash
   go test ./...
   ```
2. Dry run verification (checks FCM 5228 connectivity without dns harvest):
   ```bash
   go run ./cmd/fcmhost run -workdir . -dns=false -v
   ```
3. Perform full local run to verify DNS harvesting and expansion:
   ```bash
   go run ./cmd/fcmhost run -workdir .
   ```

### Production on bj-edge
1. `fcm-hosts-next.timer` runs 4 times daily (UTC `01:17`, `07:17`, `13:17`, `19:17`) as user `fcm-runner`.
2. Each run resets `/var/lib/fcm-runner/fcm-hosts-next` to `origin/main`, tests, generates, installs the hosts files into `/srv/cagedbird/fcm-hosts-next/`, then commits and pushes them.
3. Manual refresh and logs:
   ```bash
   ssh bj-edge sudo systemctl start fcm-hosts-next.service
   ssh bj-edge journalctl -u fcm-hosts-next.service -n 50
   ```
4. Unit changes in `deploy/` are not applied automatically: copy them to `/etc/systemd/system/` and run `sudo systemctl daemon-reload`.
5. GitHub Actions only runs `go test` and `shellcheck` on code changes; it never harvests or publishes.

## Verification

- Verify Go build and test status.
- Check local generated `fcm_dual.hosts`, `fcm_ipv4.hosts`, `fcm_ipv6.hosts` files for correct format (IP host entries).
- Check remote serving URL:
  ```bash
  curl -sI https://fcm-hosts.cagedbird.cn/fcm_dual.hosts
  ```

## Guardrails

- **Push over SSH 443:** `fcm-runner` pushes with the writable repo deploy key `fcm-runner@bj-edge`; its `~/.ssh/config` maps `github.com` to `ssh.github.com:443`. Do not switch to HTTPS tokens.
- **Prevent Workflow Loop:** Generated commits MUST include `[skip ci]` in the message.
- **No Direct Remote Edits:** Do not edit served host files directly on the server. Always change the repository and let the next run publish.
