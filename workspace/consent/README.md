# 电子知情同意与医疗操作许可引擎

零外部依赖实现（Python 3.11 标准库 + SQLite WAL），覆盖**规则维护 / 现场办理 / 参与人自助**三套页面、
持久化存储与 HTTP API。所有状态变更走 `BEGIN IMMEDIATE` 单事务并追加单调事件流水，
因此签名、撤销、执行确认、材料停用等并发竞争都按**持久化先后**收敛为唯一且可说明的状态。

## 设备可信证明（三入口状态变更的强制门槛）

主体端（参与人）、站点端（现场负责人）与外部见证链接这三个会改变办理会话的入口，
其每一次状态变更都必须与**本站一台已登记、未隔离、证书在有效期内且为当前代次的终端设备证明**
在**同一笔业务事务**内原子绑定：

1. **本机密钥 + 一次性注册码**：浏览器用纯 JS Ed25519（`static/shared/ed25519.js`，零依赖 BigInt）
   本机生成密钥（私钥不出设备）；持本站现场负责人签发的一次性注册码完成登记，服务端用签发根密钥
   签发绑定 `机构/设备/可用角色/有效期/代次` 的证书。未注册浏览器没有证书，不能改变任何会话。
2. **挑战-响应落款**：变更前先领取服务端签名的短时挑战（钉死
   `动作/会话/角色/内容指纹/机构/截止时间/随机数`），终端用本机私钥对完整请求签名；提交时
   证书链、挑战签名、六+一绑定字段、终端签名逐项重算，调换机构/会话、角色或内容指纹、
   过期挑战、越权角色、跨站设备、非本机私钥一律稳定失败。
3. **凭据与变更同事务**：`sign/revoke/execute` 在同一 `BEGIN IMMEDIATE` 内先通过证明核验，
   再在业务前置校验全部通过后原子占用唯一随机数并写 `device_attestations` 凭据行——
   凭据与业务 INSERT/UPDATE 同提交或同回滚。进程在"业务落盘后、设备留痕前"这类半程崩溃，
   因二者同事务而不可能出现；崩溃恢复不会对同一随机数生成第二次变更。
4. **同载荷重试复用首个回执**：幂等落点是挑战随机数 + 被签署内容指纹（不含含随机因子的签名编码）。
   同挑战同载荷（哪怕两个标签页各自独立签名）返回同一份首次结果；同随机数换内容 → `nonce_reused`。
5. **封禁 / 旧代立即失能，历史仍可验**：隔离把设备与当前证书置 `quarantined`，轮换把旧证置
   `rotated`、新证代次 +1；二者立刻不能再领新挑战/落款，但既有签名、许可与凭据完整保留可验。
6. **修复前历史兼容**：`signatures` 的设备凭据三列可空，修复前已形成的签名/许可无凭据也继续可验。

密码学两端字节一致：服务端 `device.py` 为纯 Python 标准库 Ed25519（RFC 8032），
浏览器端为 BigInt 实现；RFC 8032 测试向量与跨语言互验（同密钥同消息签名逐字节相同）均通过。

## 运行

```bash
python3 server.py                 # 默认 http://127.0.0.1:8088，首次启动自动建库+种子
CONSENT_PORT=9000 python3 server.py
CONSENT_DB=/data/consent.db python3 server.py
```

打开 `http://127.0.0.1:8088/` 登录。演示账号（仅演示，密码为弱口令）：

| 角色 | 账号 / 密码 | 机构 |
|---|---|---|
| 规则维护员 | `admin` / `admin-pass` | 全局 |
| 现场负责人 A 院 | `sitea` / `site-pass` | INST-A |
| 现场负责人 B 院 | `siteb` / `site-pass` | INST-B |
| 参与人 王/李 | `wang` / `wang-pass`，`li` / `li-pass` | INST-A |
| 参与人 赵 | `zhao` / `zhao-pass` | INST-B |

见证者**无需账号**：现场开单/会话详情里生成一次性签名链接（`witness.html?session=…&role=witness&token=…`），
链接用后即失效。

## 可验证的场景

```bash
python3 tests/verify.py
```

脚本会启动临时库上的真实 HTTP 服务（含 SIGKILL 重启与多线程并发），58 项断言覆盖：

1. **首次完整签署** —— 三角色对同一封存指纹落款齐备才生成许可；查询返回材料版本/获准范围/尚缺条件。
2. **缺少见证者** —— 办理进度明确缺项，操作前查询与执行确认拒绝。
3. **双终端重复落款** —— 同一幂等键并发，双方拿到同一首次结果、只落一笔签名；不同目标（他人占槽/他机构）冲突收敛。
4. **办理途中停用材料** —— 在途会话立即 `blocked`，不能再签、不能对停用版开新单、不降级旧版；已发许可继续有效。
5. **修订触发再次同意** —— 新版把操作标成需再次同意后，未发生操作立即冻结，已完成操作保留旧依据，新版补签齐备解锁；无关操作不受影响。
6. **不改变许可范围的修订**（无再次同意标记）—— 既有许可不被误伤，正常放行。
7. **异常退出后接续** —— SIGKILL 重启后未结束会话可核对、签名与落款时刻不变、会话仍钉在旧版本不挪给后续版本。
8. **撤销与执行确认竞争** —— 只按事件流水 `seq` 产生一种结果；重复撤销/重复执行均幂等；撤销后无任何越权新操作。
9. 附加：跨机构列表/审计/报错 PII 隔离、维护员不能落款、未批准译文不出现在办理界面、新增用途唯一登记与撤销前记录保留。

另有两个临时压测（见会话记录）对 12 组撤销/执行并发验证两种先后顺序都能唯一收敛。

```bash
python3 tests/test_device_attestation.py   # 40 项：设备证明门槛专项
```

设备证明专项覆盖：三入口无证明一律 `401 device_attestation_required`；注册码一次性抢占与公钥冒充；
同载荷重试复用首个回执；调换内容指纹/角色/会话/机构、伪造挑战、非本机私钥、越权角色稳定失败；
被封禁硬件与旧代证书立即失能、轮换授权一次性；设备审计逐条留凭据且跨站不可见；
**两终端并发抢同一槽位只产生一笔变更与一条完成凭据、落败者随机数随事务回滚不被消费**；
真实 SIGKILL 重启后设备/隔离/凭据存活、重放不产生第二次变更；修复前无凭据的历史许可继续可验。

## 关键设计

### 封存与版本化
- `materials` 每行是一次**封存**：正文、语种、适用条件、必签角色、允许操作共同参与 SHA-256 指纹 `body_hash`。
- 同 `track_key = hash(family|机构|语种|条件JSON)` 下，正文或覆盖范围（角色/操作/再次同意标记）一旦变化，
  发布即自动 `version+1`；完全无变化返回 `409 unchanged_version`，不制造伪版本。
- 每个 track 对现场只呈现**最新现行版**；界面不允许拼接未批准译文（语种不一致直接不呈现）。

### 会话钉版与三角色签署
- 开单时把会话钉死在某个 `material_id`；后续发布新版本、停用都不会挪动它。
- 签署位按材料的 `roles_json` 创建；参与人/现场负责人需登录且机构/本人匹配，见证者持一次性令牌免登录。
- 每笔签名保存签署时的 `body_hash`；**全部**必签角色对同一份封存内容完成后，在同一事务里把会话置为
  `completed` 并生成许可。`signatures.created_at` 只由数据库事务写入，全代码库没有更新该列的入口，后台无法改落款时刻。
- 幂等：客户端 `idempotency_key`（缺省前端自动生成）+ 服务端槽位内容哈希双保险。
  同一落款人重复提交→回放首次结果；不同落款人抢同一槽位→`409 slot_filled_by_other`，以先提交者为准。

### 许可评估、再次同意与撤销
- 许可裁定者 = **最新一份覆盖该操作的许可**；它若被撤销，不回落到更旧许可复活权限。
- 再次同意冻结：同 track 出现带 `requires_reconsent` 的现行新版且版本更新时，`evaluate` 返回
  `frozen_reconsent`，并指出需要补签的版本与尚缺会话；不追溯此前已 `performed` 的记录。
- 撤销：进行中会话→`withdrawn`；已发许可→`revoked`。撤销前执行记录原样保留（仍引用旧 family/version），
  其后新操作、`sample_reuse` 的新增用途一律拒绝。
- `executions` 对 `(对象,操作,用途)` 有部分唯一索引：同一“新增用途”只能形成一次 performed。

### 隔离
- 现场接口一律限定本机构；跨机构访问对象/会话统一返回 `404 …_not_found`，报错不暴露他人存在。
- 审计：现场只见本机构事件；维护员全局可见但参与人身份与签名人姓名打码；参与人仅见本人。
- 维护员角色在服务端被拒绝任何签署（`403`），页面也无落款入口。

## 目录

```
consent/
├── server.py        # 标准库 HTTP API + 静态页路由（ThreadingHTTPServer）
├── engine.py        # 领域引擎：发布/停用/会话/签署/评估/执行/撤销/设备证明/审计（全部事务化）
├── device.py        # 纯标准库 Ed25519（RFC 8032）+ 终端证书/挑战/请求信封/规范 JSON
├── db.py            # SQLite 连接、schema、封存指纹与 track 键、设备/凭据表与迁移
├── seed.py          # 空库种子（两机构、三套账号、一份封存材料）
├── static/
│   ├── index/admin/site/subject/witness 五页 + app.js + styles.css
│   └── shared/      # ed25519.js（浏览器 BigInt Ed25519）+ device-client.js（登记/挑战/签署助手）
└── tests/
    ├── verify.py                    # 8 大场景 + 隔离附加项的端到端断言（58 项）
    ├── test_device_attestation.py   # 设备可信证明门槛/并发/重启/历史兼容（40 项）
    └── client.py                    # HTTP 客户端、并发屏障、SIGKILL 重启、DevTerminal
```

## 主要 API

| 方法 路径 | 角色 | 说明 |
|---|---|---|
| `POST /api/auth/login` | 公开 | 登录换令牌 |
| `GET  /api/server-key` | 公开 | 设备签发根公钥（库外核对证书/挑战/凭据） |
| `POST /api/materials` | admin | 封存发布（变化即新版） |
| `POST /api/materials/{id}/retire` | admin | 停用并冻结在途会话 |
| `GET /api/materials` | admin/site | 版本列表（现场限本机构） |
| `GET /api/subjects` / `GET /api/subjects/{id}/eligibility` | site | 本机构对象与吻合材料（不吻合给原因） |
| `POST /api/subjects/{id}/sessions` | site | 对吻合的现行版开单（钉版） |
| `GET /api/sessions` `GET /api/sessions/{sid}` | site/subject | 办理进度与具体缺项 |
| `POST /api/sessions/{sid}/tokens` | site | 生成见证者一次性链接（旧链接失效） |
| `POST /api/sessions/{sid}/sign` | 三类 | 参与人/现场/见证 token 签署（**body 必带 `attestation`**） |
| `POST /api/sessions/{sid}/revoke` | subject | 撤销办理意愿或许可（**必带 `attestation`**，幂等） |
| `GET  /api/subjects/{id}/check?op=&purpose=` | site | 操作前查询：版本依据/获准范围/尚缺条件 |
| `POST /api/subjects/{id}/execute` | site | 执行确认（**必带 `attestation`**，与撤销竞争按落盘先后） |
| `GET /api/subjects/{id}/permits` `/executions` | site/subject | 当前许可与历史记录 |
| `GET /api/audit` | 三类 | 事件流水（按角色过滤/打码） |
| `POST /api/devices/register-codes` `GET` | site | 签发/列出一次性设备注册码（明文仅签发时回显） |
| `POST /api/devices/register` | 公开 | 终端凭注册码+本机公钥+CSR 自证登记 |
| `POST /api/devices/challenge` | 终端 | 领取绑定动作/会话/角色/内容指纹/机构的短时挑战 |
| `POST /api/devices/inspect` | 终端 | 持证书自证查询代次/隔离状态（任何代次可查） |
| `POST /api/devices/rotate/prepare` | site | 颁发一次性轮换授权码 |
| `POST /api/devices/rotate` | 终端 | 旧+新私钥双签完成证书代次轮换 |
| `GET  /api/devices` | site | 本站设备与全部证书代次 |
| `POST /api/devices/quarantine` | site | 即时隔离设备（幂等） |
| `GET  /api/devices/audit` | site | 本站设备凭据流水（每条状态变更一条凭据） |

