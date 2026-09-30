"""持久化层：SQLite(WAL)。所有状态变更走 BEGIN IMMEDIATE 事务并写入事件流水。

关键不变量：
- 签名落款时刻 created_at 只能由数据库事务写入，代码中不存在任何更新该列的入口。
- materials / signatures / events / idempotents / audit 表均只允许 INSERT。
"""
import json
import os
import sqlite3
import time
import hashlib
import threading

DB_PATH = os.environ.get("CONSENT_DB", os.path.join(os.path.dirname(__file__), "consent.db"))
_lock = threading.Lock()
_initialized = False

SCHEMA = r"""
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS institutions(
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users(
  id TEXT PRIMARY KEY,
  inst_id TEXT REFERENCES institutions(id),   -- 规则维护员为 NULL
  role TEXT NOT NULL CHECK(role IN ('admin','site','subject')),
  login TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  pw_hash TEXT NOT NULL,
  pw_salt TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS subjects(
  id TEXT PRIMARY KEY,
  inst_id TEXT NOT NULL REFERENCES institutions(id),
  name TEXT NOT NULL,
  user_id TEXT REFERENCES users(id),          -- 可登录的参与人账号
  language TEXT NOT NULL DEFAULT 'zh',        -- 首选语种
  conditions_json TEXT NOT NULL DEFAULT '{}'
);
-- 告知材料版本：同 track(family+机构+语种+人群条件) 下正文/覆盖范围变化即新版本
CREATE TABLE IF NOT EXISTS materials(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  family TEXT NOT NULL,
  version INTEGER NOT NULL,
  inst_id TEXT NOT NULL,
  language TEXT NOT NULL,
  body TEXT NOT NULL,
  conditions_json TEXT NOT NULL,
  roles_json TEXT NOT NULL,                   -- 必签角色 ["subject","witness","site_owner"]
  scope_json TEXT NOT NULL,                   -- 允许开展的操作
  requires_reconsent INTEGER NOT NULL DEFAULT 0, -- 本版是否声明对所列操作要求再次同意
  reconsent_ops_json TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','retired')),
  track_key TEXT NOT NULL,
  body_hash TEXT NOT NULL,                    -- 封存内容指纹
  published_at TEXT NOT NULL,
  retired_at TEXT,
  UNIQUE(family, version, inst_id, language, conditions_json)
);
CREATE INDEX IF NOT EXISTS idx_materials_track ON materials(track_key, status, version);

-- 签署会话：创建时即钉死在某个封存版本，任何后续修订都不能挪动它
CREATE TABLE IF NOT EXISTS sessions(
  id TEXT PRIMARY KEY,
  subject_id TEXT NOT NULL REFERENCES subjects(id),
  material_id INTEGER NOT NULL REFERENCES materials(id),
  track_key TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('open','completed','withdrawn','blocked')),
  created_at TEXT NOT NULL,
  completed_at TEXT,
  withdrawn_at TEXT,
  blocked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_subject ON sessions(subject_id);

-- 角色签署位：材料要求的每个角色一行，等待对应落款
CREATE TABLE IF NOT EXISTS sign_slots(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL REFERENCES sessions(id),
  role TEXT NOT NULL,
  signer_name TEXT,
  token_hash TEXT,                            -- 见证者/现场一次性签名令牌
  token_used INTEGER NOT NULL DEFAULT 0,
  UNIQUE(session_id, role)
);

CREATE TABLE IF NOT EXISTS signatures(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL REFERENCES sessions(id),
  slot_id INTEGER NOT NULL REFERENCES sign_slots(id),
  role TEXT NOT NULL,
  signer_principal TEXT NOT NULL,
  signer_name TEXT NOT NULL,
  body_hash TEXT NOT NULL,                    -- 签署时核对的封存指纹
  sig_hash TEXT NOT NULL UNIQUE,              -- (会话,角色,落款人,指纹) 去重
  created_at TEXT NOT NULL,                   -- 只写不改
  device_id TEXT,                             -- 修复后：绑定的设备（旧记录为 NULL）
  cert_id TEXT,                               -- 绑定的终端证书代次
  attest_nonce TEXT                           -- 设备挑战随机数（与 device_attestations 对应）
);

CREATE TABLE IF NOT EXISTS permits(
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL UNIQUE REFERENCES sessions(id),
  subject_id TEXT NOT NULL,
  material_id INTEGER NOT NULL,
  family TEXT NOT NULL,
  track_key TEXT NOT NULL,
  version INTEGER NOT NULL,
  body_hash TEXT NOT NULL,
  scope_json TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('active','revoked')),
  issued_at TEXT NOT NULL,
  issued_seq INTEGER NOT NULL,
  revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_permits_subject ON permits(subject_id, status);

CREATE TABLE IF NOT EXISTS executions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  subject_id TEXT NOT NULL,
  op TEXT NOT NULL,
  purpose TEXT,
  permit_id TEXT REFERENCES permits(id),
  material_family TEXT,
  version INTEGER,
  result TEXT NOT NULL CHECK(result IN ('performed','denied')),
  reason TEXT,
  created_at TEXT NOT NULL
);
-- “新增用途”同一 (对象,操作,用途) 只允许形成一次合法记录；常规操作 purpose 为 NULL 不受限
CREATE UNIQUE INDEX IF NOT EXISTS idx_exec_one_purpose
  ON executions(subject_id, op, purpose) WHERE purpose IS NOT NULL AND result='performed';
CREATE INDEX IF NOT EXISTS idx_exec_subject ON executions(subject_id, op);

-- 单调事件流水：撤销与执行确认谁先落盘，以 seq 为准
CREATE TABLE IF NOT EXISTS events(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  inst_id TEXT,
  kind TEXT NOT NULL,
  subject_id TEXT,
  session_id TEXT,
  permit_id TEXT,
  material_id INTEGER,
  detail_json TEXT NOT NULL DEFAULT '{}'
);

-- 客户端幂等键 -> 首次结果；两个终端重复提交取首次结果
CREATE TABLE IF NOT EXISTS idempotents(
  key TEXT PRIMARY KEY,
  scope TEXT NOT NULL,                        -- 例如 sign:<session>:<role>
  response_code INTEGER NOT NULL,
  response_body TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_tokens(
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL
);

-- ============================================================ 设备可信登记
-- 服务端签发根密钥：首启生成、随库持久化；旧公钥始终保留，历史证明重启/换钥后仍可验
CREATE TABLE IF NOT EXISTS server_keys(
  kid INTEGER PRIMARY KEY CHECK(kid = 1),
  alg TEXT NOT NULL,
  public_hex TEXT NOT NULL,
  seed_hex TEXT NOT NULL,
  created_at TEXT NOT NULL
);

-- 现场管理员签发的一次性设备注册码（明文仅创建时回显一次，库内不可逆推）
CREATE TABLE IF NOT EXISTS register_codes(
  code_hash TEXT PRIMARY KEY,                  -- sha256(明文码)
  code_ref TEXT NOT NULL,                      -- 中性编号（审计/列表用）
  inst_id TEXT NOT NULL REFERENCES institutions(id),
  roles_json TEXT NOT NULL,                    -- 允许设备申请的落款角色
  minutes INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','consumed','revoked')),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  device_id TEXT
);

-- 已登记设备（一台终端浏览器一个设备标识；可被即时隔离）
CREATE TABLE IF NOT EXISTS devices(
  id TEXT PRIMARY KEY,                        -- D-xxxx
  inst_id TEXT NOT NULL REFERENCES institutions(id),
  device_label TEXT NOT NULL,
  current_cert_id TEXT,
  quarantined INTEGER NOT NULL DEFAULT 0,
  quarantined_reason TEXT,
  quarantined_at TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_devices_inst ON devices(inst_id);

-- 设备证书代次：绑定机构/设备/角色/有效期/代次/终端公钥；轮换置 rotated，隔离置 quarantined
CREATE TABLE IF NOT EXISTS device_certs(
  id TEXT PRIMARY KEY,                        -- C-xxxx
  device_id TEXT NOT NULL REFERENCES devices(id),
  inst_id TEXT NOT NULL,
  gen INTEGER NOT NULL,
  roles_json TEXT NOT NULL,
  public_hex TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active'
    CHECK(status IN ('active','rotated','quarantined')),
  not_before_ms INTEGER NOT NULL,
  not_after_ms INTEGER NOT NULL,
  envelope_json TEXT NOT NULL,                -- 服务端签发的自描述证书信封
  created_at TEXT NOT NULL,
  rotated_at TEXT,
  UNIQUE(device_id, gen)
);
CREATE INDEX IF NOT EXISTS idx_certs_device ON device_certs(device_id);

-- 已签发挑战（仅持久化必要绑定字段；不回显终端签名）
CREATE TABLE IF NOT EXISTS challenges(
  nonce TEXT PRIMARY KEY,
  cert_id TEXT NOT NULL REFERENCES device_certs(id),
  inst_id TEXT NOT NULL,
  action TEXT NOT NULL,
  session_id TEXT,
  role TEXT NOT NULL,
  body_digest TEXT NOT NULL,
  not_before_ms INTEGER NOT NULL,
  not_after_ms INTEGER NOT NULL,
  created_at TEXT NOT NULL
);

-- 一次性证书轮换授权码（现场管理员签发，终端须用旧+新私钥双签）
CREATE TABLE IF NOT EXISTS rotation_nonces(
  nonce TEXT PRIMARY KEY,
  cert_id TEXT NOT NULL REFERENCES device_certs(id),
  device_id TEXT NOT NULL REFERENCES devices(id),
  expires_at_ms INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0,
  used_at TEXT,
  created_at TEXT NOT NULL
);

-- 设备审计：每一次经设备证明而成立的状态变更在此留下凭据（与业务变更同一事务落盘）。
-- 非空唯一约束保证：有设备审计行必有已消费随机数；崩溃恢复不会对同一 nonce 写第二次变更。
CREATE TABLE IF NOT EXISTS device_attestations(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nonce TEXT NOT NULL UNIQUE,
  cert_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  inst_id TEXT NOT NULL,
  action TEXT NOT NULL,
  session_id TEXT,
  role TEXT NOT NULL,
  request_fp TEXT NOT NULL,
  terminal_sig TEXT NOT NULL,
  challenge_sig TEXT NOT NULL,
  target TEXT,                                  -- 业务对象（会话/参与人）
  outcome TEXT NOT NULL,                        -- signed/completed/withdrawn/revoked/performed/...
  record_ref TEXT,                              -- 业务记录引用（执行号等）
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attest_device ON device_attestations(device_id, id);
CREATE INDEX IF NOT EXISTS idx_attest_session ON device_attestations(session_id);
"""


# 对旧库的增量迁移：新增列用 "duplicate column" 容错，保证重复执行幂等。
_MIGRATIONS = [
    "ALTER TABLE signatures ADD COLUMN device_id TEXT",
    "ALTER TABLE signatures ADD COLUMN cert_id TEXT",
    "ALTER TABLE signatures ADD COLUMN attest_nonce TEXT",
]


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + ".%03dZ" % int(time.time() * 1000 % 1000)


def hash_pw(salt, pw):
    return hashlib.sha256((salt + ":" + pw).encode()).hexdigest()


def seal_body(body, inst_id, language, conditions, roles, scope):
    """封存正文+语种+适用条件+必签角色+允许操作的规范指纹。"""
    canonical = json.dumps({
        "body": body, "inst_id": inst_id, "language": language,
        "conditions": conditions, "roles": sorted(roles), "scope": scope,
    }, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def track_key(family, inst_id, language, conditions):
    c = json.dumps(conditions, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(
        f"{family}|{inst_id}|{language}|{c}".encode("utf-8")
    ).hexdigest()[:16]


def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=15, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=15000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def begin_tx(conn):
    """立即拿写锁：把签名/撤销/执行/发布的竞态强制变成持久化先后。"""
    conn.execute("BEGIN IMMEDIATE")


def init_db():
    global _initialized
    with _lock:
        if _initialized:
            return
        conn = get_conn()
        try:
            conn.executescript(SCHEMA)
            for stmt in _MIGRATIONS:
                try:
                    conn.execute(stmt)
                except sqlite3.OperationalError as e:
                    if "duplicate column" not in str(e):
                        raise
        finally:
            conn.close()
        _initialized = True
