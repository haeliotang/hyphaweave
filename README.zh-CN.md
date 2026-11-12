<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/hyphaweave-mono-inverse.svg">
    <img src="assets/hyphaweave-mono.svg" width="120" alt="Hyphaweave — Two threads, braided">
  </picture>
</p>

# Hyphaweave

**独立系统之间的公共线。**

Hyphaweave 定义 `weave-record/1`：一种在相互独立的系统之间交换与引用记录的格式。记录导出为同一套公共格式，收下时原样保存；跨系统引用一律是「来源 + id + 摘要」。每个项目的内部存储仍归它自己。本仓库包含 `weave-record/1` 的规范、JSON Schema、一致性测试向量与 Python 参考核验器。

## 状态：草案，未稳定，尚未验收

在使用本仓库的任何内容之前，请先读这一段：

- **草案，未稳定。** `weave-record/1` 目前是 v0.1 草案。格式仍可能变化，在 v1.0 之前不承诺任何兼容性。
- **尚未验收。** `weave-record/1` v0.1 **尚未**通过 J1/J2 往返验收。只有在相互独立的项目之间真正完成两次往返（导出、原样收下并核验）之后，v0.1 才算成立。H0 交付的是规范、Schema、测试向量和一个核验器，不包含往返验收。
- **已有两个实现，但尚未经外部复核。** 现在有两个相互独立的核验器：本仓库里的 Python 参考核验器，以及 H1 里程碑新增的 Rust 核验器（`verifiers/rust/`），后者只依据规范与一致性测试向量实现。Rust 核验器**尚未**经过外部复核；通过同一套向量是必要条件，但不足以证明「只看规范就能实现这个格式」，因此本仓库**不**声称独立实现的复核已经完成。
- **已公开，仍是草案。** 仓库现在是公开的，但这不代表 `weave-record/1` 已稳定：它仍是草案，v1.0 仍取决于 J1/J2 验收和第二个独立实现。核验器尚未发布到 PyPI，只能从本仓库安装。`.github/workflows/ci.yml` 与本 README 下方的本地闸门一致；本 README 不声称某次 GitHub Actions 运行已经通过。
- **范围仅限 H0。** 本仓库没有离线传输件，没有各项目的导出/导入适配器，也没有任何网络服务。
- **经过独立复核后的修订。** 本快照包含 H0 修订 1（决定 2026-11-10 #34）与修订 2（决定 2026-11-10 #42）：独立复核发现了线协议语义缺陷，修订改变了格式规则、错误码表、信任根模型、核验器与测试向量。回归集目前是**候选集**（`vectors/frozen/v0.1-candidate/`）；正式冻结在 J1/J2 验收通过后才开始。详见 [`CHANGELOG.md`](CHANGELOG.md)。

Python 核验器是参考实现，不是产品：它的用途是让规范可被测试、给第二位实现者一个对照物，并不代表格式已经定型。

## 仓库内容

| 路径 | 内容 |
| --- | --- |
| [`spec/weave-record-1.md`](spec/weave-record-1.md) | 规范性文本（RFC 2119 关键词），覆盖记录信封、引用、容器、擦除与授权。 |
| [`spec/kinds/`](spec/kinds/) | 每个已登记 `weave.*` 种类一页。 |
| [`spec/error-codes.md`](spec/error-codes.md) | 封闭的错误码与通知登记表。 |
| [`spec/offline-verification.md`](spec/offline-verification.md) | 只用常见工具（`sha256sum`、`openssl`、JSON 查看器）手工核验一个 L0 容器的步骤。 |
| [`schemas/`](schemas/) | 信封、引用、清单与已登记种类的 JSON Schema 2020-12。 |
| [`vectors/`](vectors/) | 正、反一致性测试向量，v0.1 候选回归集（J1/J2 验收后才正式冻结），故意公开的测试密钥，以及官方外部测试数据的来源记录。 |
| [`verifiers/python/`](verifiers/python/) | `hyphaweave_verify` 0.1.0 与 `hyphaweave-verify` 命令行。 |
| [`tools/`](tools/) | 独立的向量生成脚本（不 import 核验器）与各闸门脚本。 |
| [`docs/positioning.md`](docs/positioning.md) | 非规范性的定位文档：范围、非目标、职责边界与风险。 |
| [`docs/open-questions.md`](docs/open-questions.md) | 决定 2026-11-10 #34 已裁定的问题（Q1–Q33），以及仍标为 PROVISIONAL 的实现形状选择。 |

## 使用核验器

核验器需要 Python 3.11 或更新版本，运行时不联网。它的 JSON 报告是确定性的：同一输入在任何机器上输出相同的字节。

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -c verifiers/python/constraints.txt -e "verifiers/python[dev]"
```

H0 构建所用的精确依赖版本固定在 [`verifiers/python/constraints.txt`](verifiers/python/constraints.txt)；只有该文件与 `pyproject.toml` 中固定的版本有保证。本机开发环境是 Python 3.14，Python 3.11 与 3.12 未在本机实测；3.12 工作流定义在 `.github/workflows/ci.yml`，本文件不声称它已在 GitHub 上通过。

命令行接口如下：

```bash
hyphaweave-verify record <file> [--keys <dir>] [--json]
hyphaweave-verify container <dir|zip> [--keys <dir>] [--tsa-trust <pem>] [--previous <dir>]
hyphaweave-verify vectors <dir> [--tsa-trust <pem>]
hyphaweave-verify --help
hyphaweave-verify --version
```

例如，在仓库根目录下：

```bash
# 核验单条记录，用外部密钥生命周期记录作为上下文
hyphaweave-verify record path/to/record.json --keys vectors/keys/keyset

# 核验容器目录或 zip（此处未提供时间戳信任锚）
hyphaweave-verify container path/to/container

# 一致性测试向量；候选回归集也用目录参数
hyphaweave-verify vectors vectors
hyphaweave-verify vectors vectors/frozen/v0.1-candidate
```

`--keys` 指向一个密钥生命周期记录目录（取其顶层 `*.json` 文件），用于提供公钥及其声明状态，不属于被核验的容器。`--tsa-trust` 提供 L2 时间戳信任锚；`--previous` 额外核对上一份容器的清单摘要与容器内嵌链是否一致。

每次运行只向 stdout 输出一份确定性的 JSON 报告（无颜色、无进度输出）；用法与 I/O 错误只写入 stderr。退出码：`0` 表示有效（`weave.erased` 占位记录的结论为 `erased` 也算成功，或所有向量用例吻合），`1` 表示无效、不可核验或向量不吻合，`2` 表示用法或 I/O 错误。结论分为 `valid`、`invalid`、`unverifiable` 与 `erased`；当某项检查无法完成时（例如未知公钥、缺少时间戳信任锚），如实报告 `unverifiable`，绝不当作 `valid`。核验器不联网，输出不使用墙钟、区域设置、时区或当前目录。

L2 时间戳只在通过 `--tsa-trust` 提供信任锚时才验证。没有信任锚时，时间戳报告为 `present-unverified`，容器报告为 `unverifiable`。容器的 `level_verified` 恒为 `"L0"`（L1/L2 的内部哈希链无法离线复核）；L2 只有在整条时间戳链通过所提供信任锚验证时才报告 `anchor_verified: true`。`vectors/keys/tsa/` 下的 TSA 密钥与证书是公开测试材料，测试向量之外绝不要信任它们。

## 运行各闸门

在仓库根目录、已激活虚拟环境并安装 `reuse`（`python -m pip install reuse==5.0.2`）后运行：

```bash
python tools/make_keys.py --check
python tools/gen_vectors.py --check
python tools/gen_vectors_extra.py --check
python tools/gen_index.py --check
python -m pytest verifiers/python/tests -q
hyphaweave-verify vectors vectors
( cd vectors/frozen/v0.1-candidate && sha256sum -c --strict SHA256SUMS )
python tools/check_frozen.py
hyphaweave-verify vectors vectors/frozen/v0.1-candidate
python tools/check_schemas.py
python tools/check_external.py
python tools/anti_verification.py
python tools/byte_flip_gate.py
python tools/check_spec_examples.py
reuse lint
```

这些命令与 [`.github/workflows/ci.yml`](.github/workflows/ci.yml) 中的相同。本 README 不声称某一次闸门运行已经通过；请在你的检出上运行这些命令自行核对。H0 交付快照的闸门结果汇总见 [`CHANGELOG.md`](CHANGELOG.md)。

如果要在不信任任何实现的前提下手工核验一个容器，请按 [`spec/offline-verification.md`](spec/offline-verification.md) 操作：它只用 `sha256sum`、`openssl` 与一个 JSON 查看器，并用 `vectors/` 里的一个 L0 容器实例完整走一遍。

## 非目标

Hyphaweave 刻意**不**做以下事情：

- **不是身份提供方。** 它不判断谁是真人，不签发凭证，不做登录。密钥标识就是公钥指纹；DID 与网址只是提示。
- **不是区块链，也不做透明日志。** 时间锚用 RFC 3161 时间戳，一条记录可以同时带多家时间戳服务的结果。
- **不是同步服务，也不是网络。** 核验器离线运行；计划中的传输件只搬运文件，不提供服务器、中继网络或发现机制。
- **不统一存储。** 各项目内部照旧。
- **不证明事实为真。** 签名只证明哪把密钥签了哪些字节、字节未被改动。
- **不保证全网删除。** 擦除约束的是导出物与引用；已经传播出去的副本不承诺能删干净。
- **不给 agent 开例外通道。** 标签的最严传递与 `local-only` 拒绝导出，对 agent 同样有效。

更长的非规范性说明见 [`docs/positioning.md`](docs/positioning.md)。

## 许可

- 代码、JSON Schema 与一致性测试向量：**Apache-2.0**。
- 规范与文档文字：**CC-BY-4.0**。
- 品牌资产（`assets/`）：项目 logo 保留，标识为 `LicenseRef-Inceptless-Brand`；可用于指代本项目，但不得暗示官方地位或背书。
- `vectors/external/` 下的外部测试数据沿用其上游来源的许可，并记录在数据旁边。

完整许可分层与官方许可证原文的 SHA-256 见 [`LICENSING.md`](LICENSING.md)。贡献前须接受 Inceptless 贡献者许可协议（CLA v1.0，已于 2026-11-10 生效，决定 #27/#28）；仓库现在是公开的，但只有在 CLA 签署检查对本仓库生效之后才接受外部贡献。详见 [`CONTRIBUTING.md`](CONTRIBUTING.md)。

## 安全与联系

安全报告及一切联系：**support@inceptless.com** —— 这是本仓库唯一使用的联系方式。请先读 [`SECURITY.md`](SECURITY.md)：`vectors/keys/` 下的测试密钥是故意公开的测试材料，不是泄露的密钥；签名也不证明被签署的主张为真。

仓库现在是公开的；安全报告仍只发到 support@inceptless.com，而不要发到公开 issue（见 [`SECURITY.md`](SECURITY.md)）。
