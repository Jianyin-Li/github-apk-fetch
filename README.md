# github-apk-fetch

用 GitHub Actions 从多个公开镜像抓取 Google Play 应用
[`com.github.android`](https://play.google.com/store/apps/details?id=com.github.android)
（GitHub 官方 Android 客户端）的安装包，**校验签名通过后**由 CI 自己打 tag 发布 Release。

## 为什么需要 CI

本机网络到 APKPure / APKCombo / Uptodown 等镜像基本都被拦截，GitHub Runner
的网络环境能直接访问，所以抓取和校验都放在 Actions 里跑。

## 流程

1. **多源并行拉取**（同时发起，单个源失败只记日志）
   - `apkpure-xapk`：APKPure 三个 CDN 域名，取 XAPK 整包（主力）
   - `apkpure-apk`：APKPure 裸 base APK，做交叉校验 / 备用
   - `apkpure-mobile`：移动版站点，解析版本页里的直链
   - `google-play`：可选，配置 `GPLAY_EMAIL` + `GPLAY_AAS_TOKEN` 后直接从 Play
     拉 base + config splits 并打包成 XAPK（唯一真正独立的第二源）
   - `extra-urls`：仓库变量 `EXTRA_SOURCE_URLS` 追加的任意直链（逗号或换行分隔）

   > 实测 GitHub Runner 上 APKMirror、APKCombo、Uptodown、apkfab 均为 403 或
   > Cloudflare Turnstile，apkmonk / apk.support 域名已失效，Aptoide 未收录该包，
   > 因此这些源不再保留，避免每次跑一批注定失败的请求。可用的探测脚本是
   > `scripts/probe.py` 和 `scripts/probe_links.py`（手动触发 `probe` 工作流）。
2. **逐个校验（尽力而为）**
   - 文件必须是合法 zip 容器，支持 `.apk` / `.xapk` / `.apks` / `.apkm` / `.apkx` / `.zip`
   - 异型包会把内部所有 `*.apk` 拆出来，逐个 `apksigner verify`，
     要求包名一致、所有 split 同一签名
   - `aapt2 dump badging` 的 package 必须等于 `com.github.android`
   - **校验成功但签名/包名不符 → 直接丢弃，绝不发布**
   - **校验工具本身跑不起来 → 照常发布，但在 Release 里标记 `UNVERIFIED`**
3. **决定发布谁**
   - 配置了 `EXPECTED_CERT_SHA256`：签名相符的发布，不符的丢弃（推荐）
   - 未配置：verified 的按多源**签名共识**取舍，`UNVERIFIED` 的一并发布并标注，
     Release 说明会提示去固定指纹
4. **发布**：按 `v<versionName>-<versionCode>` 创建 tag 和 Release，附上所有通过校验的
   安装包（文件名带来源，含 SHA-256 表）。同一版本已存在时不重复发版，只补新资产。

### 关于 `INSTALL_FAILED_MISSING_SPLIT`

`com.github.android` 在 Play 上以 App Bundle 分发，`/b/APK/` 直链给出的是 **base APK**，
单独安装会报 `INSTALL_FAILED_MISSING_SPLIT`。所以 CI 会把 `XAPK` 整包作为独立源拉取，
校验后优先发布 XAPK；同版本存在整包时，缺 split 的裸 base 会被剔除。安装 XAPK 用
SAI（Split APKs Installer）或 APKPure 客户端。

定时任务每天 03:17 UTC 跑一次，也可以手动触发。

## 首次运行后固定签名指纹（重要）

第一轮 Release 说明里会给出 signer SHA-256。确认无误后设置为仓库变量，
之后任何换过签名的包都会被直接拒绝：

```sh
gh variable set EXPECTED_CERT_SHA256 --repo Jianyin-Li/github-apk-fetch --body '<sha256>'
```

> 只固定 **APK 签名证书**（`apksigner` 输出里的 `V2/V3 Signer` 或 `Signer #1`）。
> build-tools 37 还会打印 `Source Stamp Signer`，那是 Google Play 的来源戳，
> 不是应用签名键，CI 已经显式跳过。

## 可选 Secrets

| 名称 | 用途 |
| --- | --- |
| `NTFY_URL` | ntfy 完整 topic 地址，配置后 CI 成功/失败会推送通知 |
| `NTFY_TOKEN` | ntfy 访问令牌 |
| `GPLAY_EMAIL` | Google 账号邮箱（可选，启用 Play 直连源） |
| `GPLAY_AAS_TOKEN` | 该账号的 AAS token（可选项，见下） |

Secrets 为空时对应步骤自动跳过，仓库公开也看不到任何令牌。

### 启用 Google Play 源

Play 是唯一能绕开第三方镜像的官方通道，但需要一个已登录设备的 AAS token：

```sh
gh secret set GPLAY_EMAIL      --repo Jianyin-Li/github-apk-fetch
gh secret set GPLAY_AAS_TOKEN  --repo Jianyin-Li/github-apk-fetch
```

拿到 token 的常见方式是用 `gpapi` 或 Aurora Store 登录一次并导出 `aas_token`。
启用后 CI 会同时从 APKPure 和 Play 拉包，两者签名必须一致才会发布；Play 返回的
split 会被打包成 XAPK 一起发布。

## 本地运行

```sh
export ANDROID_HOME=/path/to/android-sdk   # 需要 build-tools 里的 apksigner / aapt2
python3 scripts/main.py --package com.github.android --slug github
```

产物在 `publish/`（可发布文件、`release-notes.md`、`release.env`、`result.json`）。
本机网络受限时通常拉不到包，这一步在 CI 里跑才有意义。

## 说明

- 安装包来自第三方镜像，仓库只做「多源交叉 + 签名校验」，不托管源码。
- 配置 AAS token 后可以同时从 Google Play 直连拉取，这是唯一绕开镜像的官方通道。
- `com.github.android` 是免费应用，仅用于分发与备份用途。
