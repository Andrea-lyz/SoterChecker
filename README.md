# SoterChecker

本地 **Soter 语义检测器**（Android 10+，无需 root）。它回答的不是"这台机器有没有 Soter"，
而是"**这台机器上的 Soter 是不是被人伪装成没有**"：把"组件确实在位"与"本应用被展示成看不见"
这两组事实分别读出来，用它们的矛盾给出判词。

## 它检查什么

- **可见性 / 可绑定**：包查询与签名、`getApplicationEnabledSetting`、组件解析、`bindService`、
  APK 路径与 SHA-256、目录与目录项、`oat`/`vdex` 布局、厂商系统包计数、多 API 交叉（14 种问法）、
  跨层复核（Java / libc / 独立原生进程三层读同一个事实）。
- **事务语义**：`com.tencent.soter.soterserver.ISoterService` 的完整调用矩阵
  （ASK / AuthKey 的生成与导出、签名会话、设备 id、删除、未知参数与错误码 `-6`/`-1000` 等）。
- **签名链**：ASK←ATTK（有 ATTK 公钥时）、AuthKey←ASK、结果←AuthKey，全部用 EMSA-PSS/SHA-256/salt=20
  自行实现校验（不依赖 Conscrypt 的 PSS 拼写）；键集与键序、`raw` 与 challenge、计数器单调。
- **判词**：状态 + 置信度 + 一句话结论 + 矛盾证据对阵（哪条通道说在位、哪条通道说看不见）。

## 判词状态

| 状态 | 含义 |
| --- | --- |
| 干净 | 组件在位可用，且事务/签名语义与活 TA 一致 |
| 检测到伪装 | 组件确实在位，但本 uid 被展示成"没有 Soter"（路径遮罩 / 冻结 / PM 隐藏任意组合） |
| 按先验判定伪装 | 所有直接通道都看不到组件，而该固件出厂预置 SoterService（依据 ROM 自带系统包） |
| 组件与原厂不符 | 组件在位但与已采样的原厂布局/哈希/签名不符 |
| 语义断裂 | 组件在位可绑定，但应答全都不像活 TA（TA 死掉或被换成假的） |
| 语义有偏差 | 组件可用、整体一致，仅少量偏差 |
| 无法自证 | 本 uid 既看不到组件也拿不到固件先验：如实说"分不清"，不说"干净" |

## 安装与使用

1. 从 Releases 下载 `SoterChecker-1.0.apk` 安装；
2. 打开即自动检查（约 3–25 秒，取决于绑定耗时），结束后是结果页：判词条 → 矛盾对阵 → 维度板 → 检查明细；
3. 若本机 Soter 要求**指纹**才会签名（原厂 TA 的正常行为，或软件 TA 的生物门控），签名链会显示"待补"，
   点「**调用指纹补全签名链**」并按一次指纹，剩余检查会继续跑完并自动刷新判词；
4. 结果页底部可复制完整报告 JSON；应用也会把报告写到
   `Android/data/com.andrealyz.soterchecker/files/sotercheck-app.json`。

## 构建

依赖：Android SDK（`platforms;android-36` + `build-tools;36.0.0`，缺失时自动退回已装的最新版本）、
JDK 17、Python 3.9+。

```bash
python build.py                                    # build/soterchecker-signed.apk
python build.py --out SoterChecker-1.0             # 指定产物名
python build.py --rename-package com.example.copy  # 装一份独立 uid 的同款（换视角观测）
```

Windows 上也可以用 `powershell -File build.ps1 -OutName SoterChecker-1.0`（最终仍调用 build.py）。

用仓库内的 `debug.keystore` 签名：这是诊断工具、不申请任何特权权限，本地与 CI 用同一把钥匙意味着
**后续构建都能覆盖安装**。

## CI

`.github/workflows/ci.yml`：push / PR / tag 触发，构建 APK 并以 artifact `SoterChecker-1.0-apk` 上传，
构建后额外用 `aapt2 dump badging` 校验包名与版本。

## 边界（诚实说明）

- **只看本应用（本 uid）的视角**。要判断"某个别的应用是否被遮"，需要把本工具与目标应用放在同一隐藏
  策略下，或用 `--rename-package` 装一份换 uid 的副本做交叉比对。
- **不涉及服务器**。腾讯服务端的设备登记与真 ATTK 签名不在范围内：本地自洽 ≠ 服务端接受。
- **常量覆盖有限**。厂商布局/大小/哈希/签名目前只有 ColorOS/OPPO 与 HyperOS/小米两行；其它厂商会如实
  标"原厂样本 未读全"。可用外部 `profiles.json`（放在应用外部目录）覆盖或扩展。
- **检测器自身若被 hook**，应用内观测不可全信：判词最多退到"按先验判定伪装 / 无法自证"，
  **永远不会说"干净"**。

## 目录

```
AndroidManifest.xml                 清单（包名 com.andrealyz.soterchecker，版本 1.0(1)）
build.py / build.ps1                构建（CI 与本地共用同一实现）
debug.keystore                      签名用调试密钥
assets/result.html                  结果页（离线单文件：判词 / 维度板 / 明细 / 复制报告）
src/com/andrealyz/soterchecker/     检查引擎（SoterCheckerActivity / Blobs / Profiles / Verdict）
src/com/tencent/soter/**            腾讯 Soter SDK 桩类（见"第三方代码"）
src/android/support/annotation/     编译期注解桩
gen/                                AIDL 生成的存根
```

## 第三方代码

`src/com/tencent/soter/**` 与 `gen/com/tencent/soter/**` 是从设备/SDK 中提取的腾讯 Soter SDK 类与
AIDL 存根，仅为编译本探针所需，**版权归腾讯所有**，不在本仓库的授权范围内。其余代码为作者所写。

## 许可

未声明开源许可证（保留所有权利）。如需复用请先联系作者。

---

## English

SoterChecker is a **local Soter-semantics detector** for Android 10+ (no root). It does not ask
"does this device have Soter"; it asks **"is the Soter on this device real, or is it being disguised
as absent?"** — by reading the two groups of facts separately (the component is here / this app is
shown nothing) and reporting their contradiction.

**What it checks**

- *Visibility and bindability*: package query and signer, `getApplicationEnabledSetting`, component
  resolution, `bindService`, APK path and SHA-256, directory and its entries, `oat`/`vdex` layout
  files, a vendor system-package census, a 14-way multi-API cross check, and a three-layer probe
  (Java / libc / an independent native process) of the same facts.
- *Transaction semantics*: the full `ISoterService` matrix (ASK and AuthKey generate/export, sign
  sessions, device id, removal, unknown-argument and error codes such as `-6` and `-1000`).
- *Signature chain*: ASK←ATTK (when an ATTK public key is supplied), AuthKey←ASK and result←AuthKey,
  verified with a self-contained EMSA-PSS/SHA-256/salt=20 implementation, plus key set and key order,
  `raw` vs challenge, and monotonic counters.
- *Verdict*: state + confidence + one-sentence conclusion + a face-off of the contradictory evidence.

**Verdict states**: Clean · Disguised · Disguised (by firmware prior) · Component mismatch ·
Semantics broken · Semantics deviating · Cannot self-prove. "Cannot self-prove" is deliberately not
"clean".

**Install and use**: download `SoterChecker-1.0.apk` from Releases, install it (Android 10+, no root)
and open it. If the Soter on this device signs only after a biometric match (the normal behaviour of a
stock TA, or a software TA with a biometric gate), the signature chain shows "pending" — press
**"Call fingerprint and complete the chain"**, touch the sensor once, and the remaining checks run and
refresh the verdict in place. The full report can be copied from the page or read from
`Android/data/com.andrealyz.soterchecker/files/sotercheck-app.json`.

**Build**: Android SDK (`platforms;android-36`, `build-tools;36.0.0`; it falls back to the newest
installed), JDK 17, Python 3.9+. `python build.py` (add `--out NAME`, or `--rename-package` to build
a sibling copy with its own uid). The APK is signed with the bundled debug keystore so local and CI
builds install over each other. CI builds and uploads the APK on every push, PR and tag.

**Boundary**: the app can only see **its own uid's vantage**; the server side (Tencent device
registration and the hardware ATTK signature) is explicitly out of scope — local self-consistency is
not server acceptance. Vendor constants cover ColorOS/OPPO and HyperOS/Xiaomi today; unknown vendors
are reported as "profile not fully read" instead of pretending to match. If the detector itself is
hooked, in-process observation cannot be trusted: the verdict degrades to "by firmware prior" or
"cannot self-prove", and never claims "clean".

**Third-party code**: `src/com/tencent/soter/**` and `gen/com/tencent/soter/**` are Tencent Soter SDK
classes and AIDL stubs extracted from the device/SDK purely to compile this probe; their copyright
belongs to Tencent and they are outside this repository's licensing. No open-source licence is granted
for the rest either — please contact the author before reuse.

