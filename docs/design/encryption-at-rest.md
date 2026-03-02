# OpenViking 静态加密技术方案 (Encryption at Rest)

> ### 🔍 待评审事项
>
> | # | 评审项 | 所在章节 | 需要决策的问题 |
> |---|--------|---------|---------------|
> | 1 | **AGFS 加密密钥来源** | §2 | 选方案 A（client 传入密钥）还是方案 B（server Root Key 派生，⭐ 推荐）？ |
> | 2 | **方案 A 异步任务处理** | §2.1 | 若选 A，异步任务用 A-2a（内存暂存）/ A-2b（持久化暂存）？ |
> | 3 | **方案 B 安全边界** | §2.4 | 若选 B，是否接受 "持有 Root Key 的 server 运维可解密所有 account" 这一安全边界？ |
>
> 以下内容已确认，无需评审：算法选型（§1）、API Key 哈希方案（§4.4）、VectorDB 不加密策略（§5）。

---

## Context

当前 OpenViking 所有 AGFS 存储层的敏感数据均以明文存储：

| 数据类型 | 当前存储位置 | 当前状态 |
|----------|-------------|---------|
| 用户 API Key | `/{account_id}/_system/users.json` (AGFS) | 明文 `secrets.token_hex(32)` |
| 文件内容 (L0/L1/L2) | `/local/{account_id}/...` (AGFS 本地) | 明文 UTF-8 文本 |
| 关系数据 | `.relations.json` (AGFS) | 明文 JSON |
| 系统账户表 | `/_system/accounts.json` (AGFS) | 明文 JSON |

### 威胁模型

OpenViking 是多租户系统，不同客户（account）的数据（资源文件、记忆、技能）都存储在同一套服务端 AGFS 中。

**核心威胁**: 有服务端存储访问权限的人（运维人员、DBA、或存储系统被入侵时的攻击者）可以直接读取任意客户的明文数据。

**防护目标**: 即使攻击者拿到了 AGFS 磁盘上的全部文件，在没有对应 account 的加密密钥的情况下，无法读取任何客户的文件内容。

### 加密范围与状态

| 数据 | 是否加密 | 方式 | 状态 |
|------|---------|------|------|
| AGFS 文件内容 | ✅ | AES-256-GCM 对称加密 | 🔍 **待评审**（密钥来源方案见第 2 节） |
| API Key | ✅ | Argon2id 单向哈希 | ✅ **已确认** |
| VectorDB | ❌ | 由 VectorDB 后端自身负责 | ✅ 已确认（详见第 5 节） |
| `ov.conf` 配置文件 | ❌ | 不加密 | ✅ 已确认 |

---

## 1. 算法选型

本方案涉及两个已确认的密码学问题，以及一个取决于 AGFS 方案选择的可选问题：

| 问题 | 描述 | 选定算法 | 状态 |
|------|------|---------|------|
| **对称加密** | 加密 AGFS 中的文件内容 | AES-256-GCM | ✅ 已确认（三个 AGFS 方案均使用） |
| **API Key 哈希** | 用户 API Key 不可逆存储，只做验证 | Argon2id | ✅ 已确认 |
| **密钥派生** | 从一个 Root Key 为每个 account 计算出各自独立的加密密钥 | HKDF-SHA256 | 取决于 AGFS 方案（方案 B 需要，方案 A 不需要） |

下面逐一说明选型过程。

### 1.1 对称加密算法选型

**需求**: 加密 AGFS 文件内容（L0/L1/L2 文本、JSON 等），需要同时保证机密性和完整性。

| 候选 | 类型 | 优势 | 劣势 | 结论 |
|------|------|------|------|------|
| **AES-256-GCM** | AEAD (加密+认证一体) | 一步完成加密和防篡改；CPU 硬件加速 (AES-NI)；TLS 1.3 / AWS S3 / GCP 标准 | 单个 key 下 IV 不可重复（用 random IV + per-file 文件密钥 规避） | ✅ **选用** |
| AES-256-CBC + HMAC-SHA256 | 加密 + 独立认证 | 同等安全性 | 需要两步操作（先加密再 HMAC），实现更复杂，容易出错（如 padding oracle 攻击） | ❌ 淘汰：GCM 一步搞定，CBC+HMAC 是历史方案 |
| ChaCha20-Poly1305 | AEAD | 软件实现性能好（无 AES 硬件时） | 现代服务器 CPU 都有 AES-NI，ChaCha20 的软件优势不再明显 | ❌ 淘汰：服务端场景 AES-GCM 更通用 |
| XChaCha20-Poly1305 | AEAD，扩展 nonce | 192-bit nonce，碰撞风险更低 | 非 NIST 标准；Python `cryptography` 库不直接支持 | ❌ 淘汰：非标准，生态支持弱 |
| AES-256-SIV | 确定性 AEAD | IV misuse 安全 | 相同明文产生相同密文（泄露重复模式）；性能比 GCM 差 | ❌ 淘汰：我们用 per-file 文件密钥 已规避 IV 重复 |

**最终选择**: **AES-256-GCM** (NIST SP 800-38D)
- 256-bit 密钥，96-bit IV（随机生成），128-bit authentication tag
- 硬件加速：Intel AES-NI / ARM ARMv8-A 原生支持，吞吐量 >1 GB/s
- 行业验证：TLS 1.3 默认 cipher suite、AWS S3 SSE-S3、GCP CMEK 均使用此算法

### 1.2 密钥派生函数 (KDF) 选型（AGFS 方案 B 适用）

> 仅方案 B 需要。用途：从一个 Root Key 为每个 account 派生出独立的加密密钥（详见 §2.5）。方案 A 不需要密钥派生。

| 候选 | 设计目标 | 优劣 | 结论 |
|------|---------|------|------|
| **HKDF-SHA256** | 从高熵密钥派生子密钥 | 专为此场景设计（RFC 5869）；微秒级计算；确定性输出 | ✅ **选用** |
| PBKDF2-SHA256 | 口令→密钥（慢速 KDF） | 我们的输入已是 256-bit 随机密钥，不需要慢速"拉伸" | ❌ 淘汰 |
| Argon2id | 口令→密钥（慢速 KDF） | 同上，且每次派生消耗 64MiB 内存 | ❌ 淘汰 |
| BLAKE3 derive_key | 密钥派生 | 非 NIST 标准；Python 生态支持弱 | ❌ 淘汰 |

**最终选择**: **HKDF-SHA256** (RFC 5869) — `info` 参数绑定 `account_id` 确保 per-account 隔离，计算开销 <1μs/次

### 1.3 API Key 哈希算法选型

**需求**: 用户 API Key 存储后只需验证（单向），不需要还原原文。需要抗暴力破解。

| 候选 | 抗 GPU/ASIC | 内存硬度 | 标准化 | 结论 |
|------|------------|---------|--------|------|
| **Argon2id** | ✅ 强 | ✅ 可配置（64MiB+） | RFC 9106, 2015 PHC 冠军 | ✅ **选用** |
| bcrypt | ✅ 中等 | ❌ 固定 4KB | 事实标准，无 RFC | 备选方案，但内存硬度不如 Argon2id |
| scrypt | ✅ 强 | ✅ 可配置 | RFC 7914 | 参数调优复杂（N/r/p），Argon2id 更易用 |
| PBKDF2-SHA256 | ❌ 弱（纯 CPU） | ❌ 无 | NIST SP 800-132 | ❌ 淘汰：无内存硬度，GPU 可轻松暴力破解 |
| SHA-256 (直接) | ❌ 无 | ❌ 无 | — | ❌ 淘汰：快速哈希，几乎无暴力破解成本 |

**最终选择**: **Argon2id** (RFC 9106)
- Argon2 的混合变体：前半段用 Argon2i（抗侧信道），后半段用 Argon2d（抗 GPU tradeoff）
- 参数: `memory=64MiB, iterations=3, parallelism=4`
- 单次验证 ~50ms，可接受

### 1.4 算法总览

| 问题领域 | 算法 | 标准/RFC | 状态 |
|----------|------|---------|------|
| 文件内容加密 | AES-256-GCM | NIST SP 800-38D | ✅ 已确认 |
| 密钥派生 | HKDF-SHA256 | RFC 5869 | 取决于 AGFS 方案选择（方案 B 需要） |
| API Key 哈希 | Argon2id | RFC 9106 | ✅ 已确认 |

### 1.5 引用的密钥管理标准

| 标准 | 用途 |
|------|------|
| **NIST SP 800-57 Part 1** | 密钥生命周期管理指南：密钥生成、分发、存储、轮换、销毁 |
| **Envelope Encryption** (AWS/GCP/Azure 通用模式) | 分层密钥架构：数据密钥被更高层密钥保护，层层嵌套 |

---

## 2. AGFS 文件加密：密钥来源方案 🔍 待评审

AGFS 加密的核心问题是：**加密密钥从哪来、谁持有**。这决定了安全边界和系统复杂度。

### 2.1 方案 A：Client 传入密钥

**工作方式**: 每个 account 有自己的加密密钥，由 client 持有。每次 API 请求通过 Header（如 `X-Encryption-Key`）携带密钥。Server 只在请求处理期间持有密钥，不落盘、不存储。

```
Client                           Server                          AGFS
  │  请求 + X-Encryption-Key       │                               │
  │───────────────────────────────>│  encrypt(key, content)        │
  │                                │──────────────────────────────>│ 写入密文
  │  请求 + X-Encryption-Key       │                               │
  │───────────────────────────────>│  decrypt(key, ciphertext)     │
  │<───────────────────────────────│<──────────────────────────────│ 读取密文
  │         返回明文                │    密钥不落盘                  │
```

**安全边界**: server 不存储密钥，运维人员即使有磁盘 + 进程访问权限，也无法解密（密钥不在 config 里，只在请求内存中短暂存在）。

**优点**:
- 安全性最强：server 不持有任何密钥材料，即使 server 被完全入侵也无法解密历史数据
- 无需 KMS / Root Key 等基础设施，密钥管理完全由 client 负责
- 天然支持 per-account 密钥隔离

**缺点**:
- 异步任务需要额外改造（见下方子方案）
- client 必须自行安全保管密钥，丢失则数据永久不可恢复
- 每次请求都要传输密钥，增加传输面风险（必须 TLS）
- client API 侵入性高，所有请求都要带 `X-Encryption-Key` Header

**需要解决的问题**:
- ⚠️ **异步任务**: `add_resource()` 返回后，后台 SemanticQueue 异步生成 L0/L1 并写入 AGFS，此时没有 client 请求上下文

| 异步解决子方案 | 做法 | 代价 |
|---------------|------|------|
| A-2a: 内存暂存 | 密钥关联到 queue task 暂存内存，消费后清除 | 密钥在内存中存活更久；server 重启丢失未消费 task 的密钥（数据生成丢失） |
| A-2b: 持久化暂存 | 密钥用 server 临时密钥加密后随 task 持久化到队列存储，消费后删除 | 解决重启丢失问题；但 server 临时密钥本身需要安全管理（退化为类似方案 B 的信任模型） |

- ⚠️ **密钥丢失不可恢复**: client 丢了密钥，该 account 全部数据永久不可读
- ⚠️ **传输面暴露**: 每次请求传输密钥，必须 TLS 保护

**后续实施规划（如选此方案）**:
- 加密层直接用 AES-256-GCM，每个文件一个随机文件密钥，文件密钥用 client 传入的 key 加密（两层 Envelope）
- 无需 Root Key Provider / KMS 基础设施
- 需改造 API 层（新增 Header）、异步队列流程
- 密钥轮换由 client 自行管理，server 提供批量重加密 API

### 2.2 方案 B：Server 端 Root Key 派生（Envelope Encryption） ⭐ 推荐

**工作方式**: Server 自己管理一把"总钥匙"（Root Key），client 不需要知道任何加密细节。加密过程完全由 server 透明完成：

1. Server 持有一把 **Root Key**，存在 KMS 或本地文件中（全局唯一，管理员配置）
2. 每个 account 的加密密钥不是单独存储的，而是用 HKDF 从 Root Key **实时算出来**的：`HKDF(Root Key, "acc_teamA") → teamA 专用密钥`。这把派生密钥叫 **account 密钥**（行业术语 KEK, Key Encryption Key）
3. 每次写文件时，再生成一把**一次性随机密钥**叫 **文件密钥**（行业术语 DEK, Data Encryption Key），用文件密钥加密文件内容，再用 account 密钥加密文件密钥本身
4. 最终写入磁盘的是：**加密后的文件密钥 + 加密后的文件内容**（这种"钥匙和锁一起存，但钥匙本身也是锁着的"模式叫 Envelope Encryption）

```
Client                           Server                                     AGFS 磁盘
  │                                │                                           │
  │  正常请求（不带任何密钥）         │                                           │
  │───────────────────────────────>│                                           │
  │                                │  ① 算出 account 密钥:                     │
  │                                │    account密钥 = HKDF(Root Key, account_id)│
  │                                │  ② 生成本次文件专用随机密钥:                 │
  │                                │    文件密钥 = random 256-bit               │
  │                                │  ③ 用文件密钥加密文件内容                    │
  │                                │  ④ 用 account 密钥加密文件密钥               │
  │                                │─────────────────────────────────────────>│ 写入 [加密的文件密钥 + 密文]
  │                                │                                           │
  │  读取请求                       │                                           │
  │───────────────────────────────>│<─────────────────────────────────────────│ 读取 [加密的文件密钥 + 密文]
  │                                │  ① account密钥 = HKDF(Root Key, account_id)│
  │                                │  ② 用 account 密钥解密文件密钥               │
  │                                │  ③ 用文件密钥解密文件内容                    │
  │<───────────────────────────────│  返回明文                                  │
```

**安全边界**: 磁盘上全是密文，直接访问存储（运维 / DBA / 磁盘被盗）无法读取。但 server 运行时持有 Root Key，因此**有 Root Key 访问权限的人可以解密所有 account 的数据**。

**优点**:
- client API 零侵入，现有接口完全不变
- 异步任务天然兼容，server 随时可派生 account 密钥加解密
- 实现复杂度最低，密钥不需要额外存储（从 Root Key 实时算出）
- 行业标准模式：AWS S3 SSE-KMS、GCP CMEK 均采用此架构

**缺点**:
- server 持有 Root Key，有权限的运维可解密所有 account（安全边界弱于方案 A）
- 不支持单个 account 独立密钥轮换（Root Key 轮换 = 全量重加密）
- Root Key 是单点：丢失 Root Key = 全部数据不可恢复

**推荐理由**: 在威胁模型（防存储层直接访问）下提供了足够的安全保障，同时对现有架构冲击最小。Root Key 的保护可通过 KMS（Vault / AWS KMS）进一步加强，这是云厂商和行业的标准做法。

**后续实施规划（如选此方案）**:
- 三层密钥架构（详见下方 2.5 节详细设计）
- Root Key Provider 支持三种模式：本地文件、HashiCorp Vault Transit、AWS KMS（详见第 3 节）
- 密钥轮换：Root Key 轮换需全量重加密；文件密钥随文件更新自然轮换（详见第 6 节）
- 对 client API 零侵入，异步任务天然兼容

### 2.3 方案对比

| 维度 | A: Client 传入密钥 | B: Server Root Key 派生 ⭐ 推荐 |
|------|-------------------|-------------------|
| **server 能否解密** | ❌ 不能 | ✅ 能（持有 Root Key） |
| **client API 侵入性** | 高（每次请求带 key） | 无 |
| **异步任务兼容** | 需改造 | 天然兼容 |
| **密钥丢失风险** | client 丢 = 数据丢失 | 丢 Root Key = 全部丢失 |
| **实现复杂度** | 中 | 低 |
| **行业参考** | Tresorit、ProtonMail | AWS S3 SSE-KMS、GCP CMEK |

### 2.4 待评审决策点

1. **选哪个方案？** 推荐方案 B（架构冲击最小、行业标准）；方案 A 安全性最强但对异步架构有冲击
2. **如果选方案 A，异步任务选 A-2a（内存暂存）/ A-2b（持久化暂存）？**
3. **如果选方案 B，是否接受 "server 运维可解密" 这个安全边界？**

---

以下第 2.5 ~ 第 3 节为方案 B 的详细设计。方案确认后按需调整。

### 2.5 三层模型与 OpenViking 组件映射（方案 B 详细设计）

本方案采用 Envelope Encryption（信封加密）三层密钥模型。下面用 OpenViking 的实际组件说明每一层对应什么：

```
┌─────────────────────────────────────────────────────────────────┐
│  第 1 层: Root Key（根密钥）                                      │
│                                                                   │
│  对应: 整个 OpenViking 实例（全局唯一）                             │
│  存储: KMS 服务内 / ~/.openviking/master.key                      │
│  管理者: 系统管理员（ROOT 角色）                                    │
│  职责: 派生出所有 account 密钥                                     │
└───────────────────────┬─────────────────────────────────────────┘
                        │ HKDF-SHA256(Root Key, account_id) 派生
                        ▼
┌─────────────────────────────────────────────────────────────────┐
│  第 2 层: account 密钥（行业术语 KEK, Key Encryption Key）         │
│                                                                   │
│  对应: 一个 account（即 APIKeyManager 中的一个 workspace）          │
│  数量: 每个 account_id 一把，如 acc_teamA 一把、acc_teamB 一把      │
│  存储: 不存储，运行时从 Root Key + account_id 实时派生              │
│  隔离: acc_teamA 的 account 密钥无法解密 acc_teamB 的任何文件       │
│  职责: 加密该 account 下所有文件的文件密钥                          │
└───────────────────────┬─────────────────────────────────────────┘
                        │ AES-256-GCM(account 密钥, 文件密钥) 加密
                        ▼
┌─────────────────────────────────────────────────────────────────┐
│  第 3 层: 文件密钥（行业术语 DEK, Data Encryption Key）            │
│                                                                   │
│  对应: AGFS 中的单个文件（L0/L1/L2、relations、users.json 等）      │
│  数量: 每次 VikingFS.write() 调用生成一把新的                       │
│  存储: 加密后嵌入文件头部（envelope），与密文在一起                   │
│  职责: 加密该文件的实际内容                                         │
└─────────────────────────────────────────────────────────────────┘
```

#### 用实际例子走一遍

假设 account `acc_teamA` 的用户上传了一个 Python 文件，路径为 `viking://resources/utils.py`：

**写入流程** (`VikingFS.write()`):

```
1. VikingFS 将 URI 转为 AGFS 路径:
   viking://resources/utils.py → /local/acc_teamA/resources/utils.py

2. 获取 account 密钥（实时派生，不存储）:
   teamA的account密钥 = HKDF-SHA256(Root Key, info="openviking:kek:v1:acc_teamA")

3. 生成随机文件密钥:
   文件密钥 = os.urandom(32)  → 本次写入专用，用完丢弃

4. 用文件密钥加密文件内容:
   加密后内容 = AES-256-GCM(文件密钥, "def helper(): ...")

5. 用 account 密钥加密文件密钥:
   加密后文件密钥 = AES-256-GCM(teamA的account密钥, 文件密钥)

6. 写入 AGFS 磁盘文件:
   /local/acc_teamA/resources/utils.py = [OVE1 头 | 加密后文件密钥 | 加密后内容]
```

随后语义队列生成 L0/L1 摘要，同样加密存储：
```
/local/acc_teamA/resources/.abstract.md   → [OVE1 | 文件密钥2 加密 | "Python 工具函数文件"]
/local/acc_teamA/resources/.overview.md   → [OVE1 | 文件密钥3 加密 | "包含 helper() 函数..."]
```

每个文件用不同的文件密钥，但都由同一个 teamA 的 account 密钥保护。

**读取流程** (`VikingFS.read()`):

```
1. 从 AGFS 读取原始字节
2. 检查前 4 字节 == b"OVE1" → 是加密文件
3. 从 RequestContext 获取 account_id = "acc_teamA"
4. 派生 teamA的account密钥 = HKDF(Root Key, "acc_teamA")
5. 从 envelope 头部取出加密后文件密钥 → 用 account 密钥解密 → 得到文件密钥
6. 用文件密钥解密文件内容 → 返回明文
```

**跨 account 隔离**:

```
acc_teamB 的用户试图读取 acc_teamA 的文件:
→ 即使绕过路径检查拿到了密文
→ 派生的 teamB的account密钥 = HKDF(Root Key, "acc_teamB") ≠ teamA的account密钥
→ 无法解密文件密钥 → 解密失败 → InvalidTag 异常
```

#### 为什么需要三层而不是更简单的方案

**方案对比**:

| 方案 | 描述 | 问题 |
|------|------|------|
| 单层：Root Key 直接加密所有文件 | 所有文件共用一个密钥 | Root Key 泄露 = 所有数据泄露；无法做 per-account 隔离；单个密钥下 IV 碰撞风险大 |
| 两层：Root Key → account 密钥直接加密文件 | 每个 account 一把密钥直接加密内容 | account 密钥轮换时要重加密该 account 的**全部文件内容**（可能 GB 级别）；单密钥加密大量文件有 IV 碰撞风险 |
| **三层：Root Key → account 密钥 → 文件密钥** | 每个文件独立文件密钥 | ✅ account 密钥轮换只需重加密文件密钥（每个 32 字节），无需重加密文件内容；每个文件密钥只加密一个文件，IV 碰撞概率为零；单文件泄露不影响其他文件 |

结论：三层是 Envelope Encryption 的标准实践（AWS S3 SSE-KMS、GCP CMEK、Azure Key Vault 均采用此模型），它在安全性、轮换效率、隔离粒度之间取得了最佳平衡。

#### account 密钥派生算法

```python
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def derive_account_key(root_key: bytes, account_id: str) -> bytes:
    """从 Root Key 派生 per-account 密钥 (HKDF-SHA256, RFC 5869)

    示例:
      derive_account_key(root_key, "acc_teamA") → 固定的 32 字节 account 密钥
      derive_account_key(root_key, "acc_teamB") → 另一个完全不同的 32 字节 account 密钥
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,                                          # 256-bit output
        salt=b"openviking-kek-salt-v1",                     # 固定 salt，版本化
        info=f"openviking:kek:v1:{account_id}".encode(),    # account_id 绑定
    )
    return hkdf.derive(root_key)
```

关键设计决策：
- `salt` 固定为常量——因为 Root Key 本身已是 256-bit 随机密钥（高熵），不需要 salt 增加熵
- `info` 包含 `account_id`——确保不同 account 的密钥互不相同
- `v1` 版本号——为未来算法升级预留
- account 密钥是**确定性**的：给定 Root Key + account_id 总能重建同一把 account 密钥，无需额外存储

#### 文件密钥生成与 Envelope

```python
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt_file(account_key: bytes, plaintext: bytes) -> bytes:
    """Envelope Encryption: 生成文件密钥 → 加密内容 → 加密文件密钥 → 组装

    对应 VikingFS.write() 中的加密步骤。
    每次调用生成全新的文件密钥，保证文件间密钥独立。
    """
    # 1. 生成随机文件密钥（本次写入专用）
    file_key = os.urandom(32)  # 256-bit

    # 2. 用文件密钥加密文件内容
    data_iv = os.urandom(12)  # 96-bit
    data_cipher = AESGCM(file_key)
    encrypted_content = data_cipher.encrypt(data_iv, plaintext, None)
    # encrypted_content = ciphertext || tag (GCM 模式自动附加 16-byte auth tag)

    # 3. 用 account 密钥加密文件密钥（这就是 "envelope" 的含义——把密钥装进信封）
    key_iv = os.urandom(12)
    account_cipher = AESGCM(account_key)
    encrypted_file_key = account_cipher.encrypt(key_iv, file_key, None)
    # encrypted_file_key = encrypted_key(32) || tag(16) = 48 bytes

    # 4. 组装：[魔术字节 | 加密的文件密钥 | 密钥IV | 内容IV | 加密的内容]
    return b"OVE1" + encrypted_file_key + key_iv + data_iv + encrypted_content
```

---

## 3. Root Key Provider 详细设计（方案 B 适用）

> 本节仅在 AGFS 加密方案选定为 B 时适用。方案 A（client 传入密钥）不需要 Root Key Provider。

方案 B 的核心是 server 持有一把 Root Key。但 **Root Key 本身存在哪里、怎么获取**？这就是 Root Key Provider 要解决的问题。

不同部署环境对 Root Key 的安全要求不同：开发环境放本地文件即可，生产环境需要专业的密钥管理服务（KMS）来保护。Provider 是对"Root Key 从哪来"的抽象，让加密逻辑不用关心 Root Key 的存储方式。

提供三种 Provider 实现：

### 3.1 Provider 抽象接口

```python
from abc import ABC, abstractmethod

class RootKeyProvider(ABC):
    """Root Key 提供者抽象接口"""

    @abstractmethod
    async def get_root_key(self) -> bytes:
        """获取 256-bit Root Key。
        返回值必须是 32 字节的密钥材料。
        实现方应缓存密钥以避免重复的远程调用。
        """
        ...

    @abstractmethod
    async def encrypt_file_key(self, plaintext_key: bytes) -> bytes:
        """加密一个文件密钥（用于 envelope 操作）。
        Local 模式下用本地 AES-256-GCM 加密。
        KMS 模式下调用远程 Encrypt API。
        """
        ...

    @abstractmethod
    async def decrypt_file_key(self, encrypted_key: bytes) -> bytes:
        """解密一个文件密钥。"""
        ...
```

### 3.2 Local File Provider（自托管/开发环境）

**适用场景**: 本地开发、单机部署、不依赖外部服务的自托管环境。

**工作原理**:
1. Root Key 是一个 32-byte 随机密钥，存储在本地文件中
2. 文件权限严格限制为 `0600`（仅 owner 可读写）
3. 首次启动时自动生成，或由管理员手动提供

**密钥文件格式** (`~/.openviking/master.key`):
```
# 32 字节密钥的 hex 编码，共 64 个 hex 字符
a1b2c3d4e5f6...（64 hex chars）
```

**配置**:
```json
{
  "encryption": {
    "enabled": true,
    "provider": "local",
    "local": {
      "key_file": "~/.openviking/master.key"
    }
  }
}
```

**初始化流程**:
```
启动 → 读取 key_file → 验证文件权限 (必须 0600)
  → 解析 hex → 验证长度 (== 32 bytes)
  → 缓存到内存 → 就绪
```

**安全考量**:
- 密钥文件不应纳入版本控制（加入 `.gitignore`）
- 备份时需要单独安全地备份此文件，否则所有加密数据不可恢复
- 适合单机部署；多节点集群需要安全地分发此文件到每个节点

**首次生成命令**（CLI 工具提供）:
```bash
openviking-cli crypto init-key --output ~/.openviking/master.key
# 内部实现: os.urandom(32).hex() → write to file → chmod 0600
```

### 3.3 HashiCorp Vault Provider（推荐用于生产多节点部署）

**适用场景**: 生产环境、多节点集群、需要审计日志和自动轮换的场景。

**工作原理**:
1. Vault 的 **Transit Secrets Engine** 提供 "加密即服务"（Encryption as a Service）
2. Root Key 在 Vault 内部生成和存储，**永远不离开 Vault**
3. OpenViking 通过 Vault API 执行 encrypt/decrypt 操作
4. Vault 自身有密封/解封（seal/unseal）机制保护存储

**配置**:
```json
{
  "encryption": {
    "enabled": true,
    "provider": "vault",
    "vault": {
      "addr": "https://vault.example.com:8200",
      "auth_method": "token | approle | kubernetes",
      "token": "hvs.xxxxx",
      "approle": {
        "role_id": "xxx",
        "secret_id": "xxx"
      },
      "kubernetes": {
        "role": "openviking",
        "jwt_path": "/var/run/secrets/kubernetes.io/serviceaccount/token"
      },
      "transit_key_name": "openviking-root",
      "transit_mount_path": "transit"
    }
  }
}
```

**Vault Transit Engine 交互协议**:

```
1. 创建 Transit Key（一次性，由管理员操作）:
   vault write transit/keys/openviking-root type=aes256-gcm96

2. 加密文件密钥（OpenViking → Vault）:
   POST /v1/transit/encrypt/openviking-root
   {
     "plaintext": "<base64(文件密钥)>",
     "context": "<base64(account_id)>"    ← 派生上下文，实现 per-account 密钥
   }
   Response: { "ciphertext": "vault:v1:xxxx" }

3. 解密文件密钥（OpenViking → Vault）:
   POST /v1/transit/decrypt/openviking-root
   {
     "ciphertext": "vault:v1:xxxx",
     "context": "<base64(account_id)>"
   }
   Response: { "plaintext": "<base64(文件密钥)>" }

4. 密钥轮换（管理员操作）:
   POST /v1/transit/keys/openviking-root/rotate
   → Vault 自动保留旧版本用于解密，新加密使用新版本
```

**Vault 认证方式说明**:

| 认证方式 | 适用场景 | 说明 |
|----------|---------|------|
| `token` | 开发/测试 | 直接提供 Vault token，简单但需手动管理 token 过期 |
| `approle` | 生产 VM/容器 | Role ID + Secret ID，Secret ID 可设置使用次数和 TTL |
| `kubernetes` | K8s 集群 | 利用 K8s ServiceAccount JWT 自动认证，零额外凭证管理 |

**Vault 模式下的密钥层次简化**:

在 Vault 模式下，不再使用 HKDF 本地派生 account 密钥，而是利用 Vault Transit 的 `context` 参数实现 per-account 密钥派生（Vault 内部做 HKDF）：

```
Vault Transit Key (Root Key, 存在 Vault 内)
    │
    │  context=account_id → Vault 内部派生出 per-account 密钥
    ▼
文件密钥 (per 文件，由 OpenViking 随机生成)
    → 发送给 Vault 加密 → 密文存入 envelope
```

这省去了显式的 account 密钥层，因为 Vault Transit 的 `context` 参数原生支持 derived key 功能。

**Python 依赖**: `hvac` (HashiCorp Vault client for Python)

**核心实现逻辑**:
```python
import hvac

class VaultProvider(RootKeyProvider):
    def __init__(self, config):
        self.client = hvac.Client(url=config.addr, token=config.token)
        self.key_name = config.transit_key_name
        self.mount = config.transit_mount_path

    async def encrypt_file_key(self, plaintext_key: bytes, account_id: str) -> bytes:
        resp = self.client.secrets.transit.encrypt_data(
            name=self.key_name,
            plaintext=base64.b64encode(plaintext_key).decode(),
            context=base64.b64encode(account_id.encode()).decode(),
            mount_point=self.mount,
        )
        return resp["data"]["ciphertext"].encode()

    async def decrypt_file_key(self, ciphertext: bytes, account_id: str) -> bytes:
        resp = self.client.secrets.transit.decrypt_data(
            name=self.key_name,
            ciphertext=ciphertext.decode(),
            context=base64.b64encode(account_id.encode()).decode(),
            mount_point=self.mount,
        )
        return base64.b64decode(resp["data"]["plaintext"])
```

### 3.4 AWS KMS Provider（AWS 云部署）

**适用场景**: 部署在 AWS 上的生产环境。

**工作原理**:
1. 在 AWS KMS 创建 Customer Master Key (CMK)
2. CMK 存储在 AWS HSM 中，永远不可导出
3. OpenViking 调用 KMS `GenerateDataKey` / `Decrypt` API 进行 envelope 操作
4. AWS 自动处理密钥轮换、审计日志（CloudTrail）、访问控制（IAM Policy）

**配置**:
```json
{
  "encryption": {
    "enabled": true,
    "provider": "aws_kms",
    "aws_kms": {
      "key_id": "arn:aws:kms:us-east-1:123456789:key/abc-def-123",
      "region": "us-east-1",
      "endpoint_url": null,
      "profile": null
    }
  }
}
```

**AWS KMS 交互协议**:

```
1. 创建 CMK（一次性，由管理员操作）:
   aws kms create-key --key-spec SYMMETRIC_DEFAULT --key-usage ENCRYPT_DECRYPT

2. 生成文件密钥（OpenViking → KMS）:
   kms.GenerateDataKey(
     KeyId = "arn:aws:kms:...",
     KeySpec = "AES_256",
     EncryptionContext = {"account_id": "acc_xxx", "service": "openviking"}
   )
   Response: {
     Plaintext: <32 bytes 文件密钥>,        ← 用于加密文件内容
     CiphertextBlob: <加密后的文件密钥>     ← 存入 envelope 头部
   }

3. 解密文件密钥（OpenViking → KMS）:
   kms.Decrypt(
     CiphertextBlob = <加密后的文件密钥 from envelope>,
     EncryptionContext = {"account_id": "acc_xxx", "service": "openviking"}
   )
   Response: { Plaintext: <32 bytes 文件密钥> }

4. 密钥自动轮换:
   aws kms enable-key-rotation --key-id <key-id>
   → AWS 每年自动轮换，旧版本自动保留用于解密
```

**EncryptionContext 说明**:
- AWS KMS 的 `EncryptionContext` 是 AAD (Additional Authenticated Data)
- 解密时必须提供完全一致的 context，否则解密失败
- 绑定 `account_id` 确保文件密钥不能被跨 account 使用
- 所有 KMS 调用自动记录到 CloudTrail（审计日志）

**AWS KMS 模式下的密钥层次简化**（与 Vault 类似）:

```
AWS CMK (存在 KMS HSM 内，不可导出)
    │
    │  EncryptionContext={"account_id": "xxx"} → 绑定 account
    ▼
文件密钥 (per 文件，KMS GenerateDataKey 生成)
    → CiphertextBlob 存入 envelope
```

**Python 依赖**: `boto3` (AWS SDK)

**核心实现逻辑**:
```python
import boto3

class AWSKMSProvider(RootKeyProvider):
    def __init__(self, config):
        self.kms = boto3.client("kms", region_name=config.region)
        self.key_id = config.key_id

    async def generate_file_key(self, account_id: str) -> tuple[bytes, bytes]:
        """返回 (明文文件密钥, 加密后文件密钥)"""
        resp = self.kms.generate_data_key(
            KeyId=self.key_id,
            KeySpec="AES_256",
            EncryptionContext={"account_id": account_id, "service": "openviking"},
        )
        return resp["Plaintext"], resp["CiphertextBlob"]

    async def decrypt_file_key(self, encrypted_file_key: bytes, account_id: str) -> bytes:
        resp = self.kms.decrypt(
            CiphertextBlob=encrypted_file_key,
            EncryptionContext={"account_id": account_id, "service": "openviking"},
        )
        return resp["Plaintext"]
```

### 3.5 Provider 对比总结

| 特性 | Local File | HashiCorp Vault | AWS KMS |
|------|-----------|-----------------|---------|
| Root Key 存储位置 | 本地文件 | Vault 服务器 HSM/软件 | AWS HSM（FIPS 140-2 L2） |
| Root Key 是否可导出 | 是（文件即密钥） | 否（Transit Engine） | 否（CMK 不可导出） |
| 认证方式 | 文件系统权限 | Token / AppRole / K8s | IAM Role / AccessKey |
| 审计日志 | 无 | Vault Audit Log | CloudTrail |
| 自动轮换 | 手动 | API 触发 | 自动年度轮换 |
| 多节点支持 | 需手动分发 key file | 原生支持 | 原生支持 |
| 依赖 | 无额外依赖 | `hvac` | `boto3` |
| 适用场景 | 开发/单机 | 生产/多云/多节点 | AWS 云部署 |
| 网络依赖 | 无 | Vault 服务可用性 | AWS KMS 服务可用性 |

---

## 4. 数据加密方案详细设计（方案 B 适用，方案 A 可简化复用）

### 4.1 加密文件二进制格式 (Envelope Format v1)

```
Offset  Size    Field                   Description
──────  ──────  ──────────────────────  ──────────────────────────────────────
0x00    4       magic                   固定值 b"OVE1"，用于识别加密文件
0x04    1       provider_type           0x01=local, 0x02=vault, 0x03=aws_kms
0x05    2       encrypted_key_length    加密后文件密钥的字节长度（大端序）
                                        - Local: 48 (32+16 tag)
                                        - Vault: 变长 ("vault:v1:xxx")
                                        - AWS: 变长 (CiphertextBlob)
0x07    var     encrypted_file_key      加密后的文件密钥
var     12      key_iv                  加密文件密钥时的 IV（仅 Local 模式使用）
var     12      data_iv                 加密文件内容时的 IV
var     var     encrypted_content       AES-256-GCM(文件密钥, plaintext)
                                        末尾 16 bytes 是 GCM auth tag
```

**Magic Bytes 检测**:
- 读取文件时先检查前 4 字节
- 如果是 `OVE1` → 走解密路径
- 否则 → 明文文件，直接返回（支持渐进式迁移）

### 4.2 AGFS 文件加密范围

| 文件类型 | 路径示例 | 是否加密 | 理由 |
|----------|---------|---------|------|
| L0 摘要 | `resource/.abstract.md` | ✅ | 含语义摘要信息 |
| L1 概览 | `resource/.overview.md` | ✅ | 含结构化内容概览 |
| L2 完整内容 | `resource/file.py` | ✅ | 原始文件内容 |
| 关系数据 | `.relations.json` | ✅ | 含资源间关联关系 |
| 用户注册表 | `{account_id}/_system/users.json` | ✅ | 含用户身份信息（key 已哈希） |
| 账户列表 | `/_system/accounts.json` | ✅ | 含所有 account 信息 |
| 目录结构 | 目录名、文件名 | ❌ | 需要遍历和路径匹配 |
| 集合元数据 | `collection_meta.json` | ❌ | VectorDB 本地元数据，需直接读取 |

### 4.3 VikingFS 集成点

加解密在 `VikingFS` 的 `read()` / `write()` 方法中透明实现：

```python
# openviking/storage/viking_fs.py

class VikingFS:
    def __init__(self, ..., encryptor: Optional[FileEncryptor] = None):
        self._encryptor = encryptor  # 注入加密器，None 表示不加密

    async def write(self, uri: str, content: str, ctx: RequestContext):
        account_id = ctx.user_identifier.account_id
        path = self._uri_to_path(uri, ctx)
        raw = content.encode("utf-8")

        if self._encryptor:
            raw = await self._encryptor.encrypt(account_id, raw)

        await self._agfs.write(path, raw)

    async def read(self, uri: str, ctx: RequestContext) -> str:
        path = self._uri_to_path(uri, ctx)
        raw = await self._agfs.read(path)

        if self._encryptor and raw[:4] == b"OVE1":
            account_id = ctx.user_identifier.account_id
            raw = await self._encryptor.decrypt(account_id, raw)

        return raw.decode("utf-8")
```

关键点：
- `_encryptor` 通过依赖注入传入，与 VikingFS 解耦
- 读取时通过 magic bytes 自动检测是否需要解密
- 未加密文件（明文）仍可正常读取，支持渐进式迁移

### 4.4 API Key 哈希存储 ✅ 已确认

API Key 的安全目标与文件内容不同——只需**验证**，不需要还原原文。因此使用**单向哈希**而非可逆加密。

**算法**: Argon2id (RFC 9106)

```python
from argon2 import PasswordHasher

ph = PasswordHasher(
    time_cost=3,        # 3 iterations
    memory_cost=65536,  # 64 MiB
    parallelism=4,      # 4 parallel threads
    hash_len=32,        # 32-byte output hash
    salt_len=16,        # 16-byte random salt
)

# 创建 key 时哈希存储
key_plaintext = secrets.token_hex(32)          # 生成 API Key
key_hash = ph.hash(key_plaintext)              # → "$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>"
# key_plaintext 返回给用户，仅此一次
# key_hash 存入 users.json

# 验证时
try:
    ph.verify(stored_hash, incoming_key)       # 匹配 → True
except argon2.exceptions.VerifyMismatchError:
    pass                                       # 不匹配
```

**`users.json` 新格式**:
```json
{
  "users": [
    {
      "user_id": "u_abc123",
      "key_hash": "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$WDGiZGRhA...",
      "key_prefix": "a1b2c3d4",
      "role": "admin",
      "created_at": "2026-03-01T00:00:00Z"
    }
  ]
}
```

**验证性能优化**:

Argon2id 单次验证 ~50ms（64MiB 内存），不能对每个请求遍历所有用户。优化方案：

```
请求到达 → 取 api_key 前 8 字符作为 prefix
  → 查内存 HashMap: {prefix → [(account_id, user_id, key_hash)]}
  → 对候选列表（通常 1 个）逐一 Argon2id verify
  → 匹配 → 返回 identity
  → 全部不匹配 → 401 Unauthorized
```

- `key_prefix` 是 key 明文的前 8 字符，存储在 `users.json` 中
- prefix 不泄露安全信息（64-bit hex 前缀，无法用于暴力破解 full key）
- 内存索引在启动时从 users.json 构建

**APIKeyManager 改动清单** (`openviking/server/api_keys.py`):

| 方法 | 当前实现 | 改动 |
|------|---------|------|
| `_load_account_keys()` | 加载明文 key → 内存 dict | 加载 (prefix, hash) → 内存 prefix index |
| `resolve()` | `key_index[key]` O(1) 查找 | prefix 过滤 + Argon2id verify |
| `register_user()` | 存储明文 key | 存储 hash + prefix |
| `regenerate_key()` | 替换明文 key | 替换 hash + prefix |
| `_build_key_index()` | `{plaintext_key → identity}` | `{prefix → [(identity, hash)]}` |

---

## 5. VectorDB 加密策略 ✅ 已确认：不加密

### 5.1 结论：不在应用层加密 VectorDB 数据

理由：

1. **向量不可加密**: 加密后的向量无法进行 ANN (Approximate Nearest Neighbor) 相似性搜索，这是 VectorDB 的核心功能
2. **托管服务自带安全**: Volcengine VikingDB 使用 HTTPS + SignerV4 签名认证，数据加密由云服务商在存储层实现
3. **Local 后端**: LevelDB 明文存储，但 local 模式用于开发环境，安全要求较低
4. **元数据冗余**: VectorDB 中的 uri、abstract 等字段在 AGFS 中已有加密副本，VectorDB 本质是索引/缓存层

### 5.2 各后端安全能力

| 后端 | 传输加密 | 存储加密 | 认证 | 建议 |
|------|---------|---------|------|------|
| `local` | N/A | ❌ 无 | N/A | 开发用，依赖 OS 文件权限 |
| `http` | 需部署反代 HTTPS | 取决于服务端 | 无内置 | 生产环境必须配 TLS |
| `volcengine` | ✅ HTTPS | ✅ 服务端加密 | ✅ SignerV4 | 已满足安全要求 |
| `vikingdb` (私有) | 取决于部署 | 取决于部署 | Header Auth | 建议配 TLS + 存储加密 |

### 5.3 未来可选增强

如果未来需要更强的 VectorDB 数据保护：
- **方案 A**: 对 VectorDB 中的 `uri`、`abstract`、`name` 等文本元数据字段做应用层加密（不影响向量搜索）
- **方案 B**: 使用同态加密或安全多方计算进行向量检索（学术研究阶段，性能开销大）

当前不实施，留作扩展点。

---

## 6. 密钥轮换 (Key Rotation)

> 本期不实现密钥轮换功能，此处仅做方案说明，待 AGFS 加密方案确认后按需支持。

密钥轮换就是**定期换一把新密钥**，让旧密钥失效。目的是限制泄露的影响范围：即使某把密钥在过去某个时间点被泄露了，攻击者也只能解密泄露之前的数据，换了新密钥之后写入的数据无法解密。

以方案 B 为例，不同层级的轮换方式和代价差异很大：

| 层级 | 轮换方式 | 代价 | 说明 |
|------|---------|------|------|
| **文件密钥** | 每次 `write()` 自动生成新的，天然轮换 | 零 | 每个文件每次写入都是新密钥，无需人工干预 |
| **Root Key (Local)** | 生成新 Root Key → 用旧密钥解密全部文件 → 用新密钥重新加密 | 高 | 需要离线全量重加密，建议周期 ≥ 1 年 |
| **Root Key (Vault)** | 调用 Vault API 轮换，Vault 自动保留旧版本用于解密历史数据 | 低 | 新数据用新版本加密，旧数据按需 rewrap |
| **Root Key (AWS KMS)** | 开启自动轮换，AWS 每年自动换一次 | 零 | 完全自动，应用层无需任何改动 |

方案 A 的密钥轮换由 client 自行管理，server 不参与。

---

## 7. 实施概要

### 7.1 主要改动点

| 改动 | 说明 |
|------|------|
| 新增 `openviking/crypto/` 模块 | RootKeyProvider 抽象 + 三种 provider 实现、KeyManager、FileEncryptor、Envelope 格式解析 |
| `openviking/storage/viking_fs.py` | `read()`/`write()` 增加透明加解密 |
| `openviking/server/api_keys.py` | 明文 key → Argon2id hash + prefix index 验证 |
| `openviking/service/openviking_service.py` | 根据 config 初始化加密组件链路 |
| 数据迁移脚本 | 存量明文文件加密 + API Key 哈希转换（不可逆，需在明文 key 存在时执行） |

### 7.2 依赖库

| 库 | 用途 | 必须/可选 |
|----|------|----------|
| `cryptography` | AES-256-GCM, HKDF-SHA256 | 必须 |
| `argon2-cffi` | API Key Argon2id 哈希 | 必须 |
| `hvac` | HashiCorp Vault 客户端 | 可选 (provider=vault) |
| `boto3` | AWS KMS 客户端 | 可选 (provider=aws_kms) |

### 7.3 验证要点

- **正确性**: envelope round-trip（encrypt → decrypt → 原文一致）；HKDF 派生确定性；跨 account 密钥隔离；API Key hash + verify
- **安全性**: 篡改密文/IV/tag → `InvalidTag` 异常；文件权限校验
- **集成**: 加密模式下 `add_resource()` → `find()`、`add_message()` → `commit()` 端到端正常
- **性能**: AES-256-GCM >1 GB/s (AES-NI)；Argon2id ~50ms/次；KMS 网络延迟可接受
