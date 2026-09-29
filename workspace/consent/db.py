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
  created_at TEXT NOT NULL                    -- 只写不改
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
"""


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
        finally:
            conn.close()
        _initialized = True
