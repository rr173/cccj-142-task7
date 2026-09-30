"""领域引擎：材料封存发布、签署会话、许可评估、再次同意、撤销/执行竞争。

所有写操作都在单个 BEGIN IMMEDIATE 事务内完成“读状态→判定→落盘→写事件流水”，
因此撤销与执行、双终端重复落款等竞争只按持久化先后收敛为一个结果。

设备可信：sign / revoke / execute 三个办理入口的状态变更，必须在同一笔业务事务内
通过设备证明（终端证书 + 短时挑战 + 终端私钥签名 + 未消费随机数），并在 device_attestations
留下凭据行；未注册浏览器、隔离设备、过期/旧代证书、异文/越权/跨站请求一律稳定失败。
"""
import json
import secrets
import hashlib
import time

import device as devmod
from device import DeviceKey, canonical_bytes
from db import get_conn, begin_tx, now, seal_body, track_key

KNOWN_OPS = ["blood_draw", "imaging", "medication", "sample_reuse"]
KNOWN_ROLES = ["subject", "witness", "site_owner"]
ROLE_LABELS = {"subject": "参与人", "witness": "见证者", "site_owner": "现场负责人"}
CHALLENGE_TTL_MS = 60_000
CERT_MINUTES = 5 * 24 * 60


class EngineError(Exception):
    def __init__(self, code, message, http=400):
        super().__init__(message)
        self.code = code
        self.http = http


def _j(row, key, default=None):
    if row is None:
        return default
    v = row[key]
    return json.loads(v) if v is not None else default


def _evt(conn, kind, *, inst_id=None, subject_id=None, session_id=None,
         permit_id=None, material_id=None, detail=None):
    conn.execute(
        "INSERT INTO events(ts,inst_id,kind,subject_id,session_id,permit_id,material_id,detail_json)"
        " VALUES(?,?,?,?,?,?,?,?)",
        (now(), inst_id, kind, subject_id, session_id, permit_id, material_id,
         json.dumps(detail or {}, ensure_ascii=False)),
    )


def _idem_get(conn, key, scope):
    r = conn.execute("SELECT response_code,response_body FROM idempotents WHERE key=? AND scope=?",
                     (key, scope)).fetchone()
    return (r["response_code"], json.loads(r["response_body"]), True) if r else None


def _idem_put(conn, key, scope, code, body):
    conn.execute(
        "INSERT OR IGNORE INTO idempotents(key,scope,response_code,response_body,created_at)"
        " VALUES(?,?,?,?,?)",
        (key, scope, code, json.dumps(body, ensure_ascii=False), now()),
    )


# ---------------- 机构 / 对象 / 认证 ----------------

def list_institutions(conn):
    return [dict(r) for r in conn.execute("SELECT * FROM institutions ORDER BY id")]


def get_subject(conn, subject_id):
    r = conn.execute("SELECT * FROM subjects WHERE id=?", (subject_id,)).fetchone()
    if not r:
        raise EngineError("subject_not_found", "参与人对象不存在", 404)
    d = dict(r)
    d["conditions"] = json.loads(d.pop("conditions_json"))
    return d


def list_subjects(conn, inst_id):
    out = []
    for r in conn.execute("SELECT * FROM subjects WHERE inst_id=? ORDER BY id", (inst_id,)):
        d = dict(r)
        d["conditions"] = json.loads(d.pop("conditions_json"))
        out.append(d)
    return out


def authenticate(conn, login, pw):
    from db import hash_pw
    r = conn.execute("SELECT * FROM users WHERE login=?", (login,)).fetchone()
    if not r or hash_pw(r["pw_salt"], pw) != r["pw_hash"]:
        raise EngineError("bad_credentials", "账号或密码错误", 401)
    token = secrets.token_urlsafe(24)
    conn.execute("INSERT INTO auth_tokens(token,user_id,created_at) VALUES(?,?,?)",
                 (token, r["id"], now()))
    _evt(conn, "login", inst_id=r["inst_id"], detail={"user_id": r["id"], "role": r["role"]})
    return token, dict(r)


def principal_from_token(conn, token):
    r = conn.execute(
        "SELECT u.* FROM auth_tokens t JOIN users u ON u.id=t.user_id WHERE t.token=?",
        (token,)).fetchone()
    if not r:
        raise EngineError("unauthenticated", "未登录或会话已失效", 401)
    d = dict(r)
    return d


# ---------------- 设备可信：签发根密钥 ----------------

def server_key(conn):
    """取（首启则生成）服务端签发根密钥。公钥可公开核对证书/挑战/记录信封。"""
    r = conn.execute("SELECT * FROM server_keys WHERE kid=1").fetchone()
    if r:
        return DeviceKey(bytes.fromhex(r["seed_hex"]))
    kp = devmod.generate_server_keypair()
    begin_tx(conn)
    conn.execute(
        "INSERT INTO server_keys(kid,alg,public_hex,seed_hex,created_at) VALUES(1,?,?,?,?)",
        (kp["alg"], kp["public_hex"], kp["seed_hex"], now()))
    conn.execute("COMMIT")
    return DeviceKey(bytes.fromhex(kp["seed_hex"]))


def server_public_hex(conn):
    return conn.execute("SELECT public_hex FROM server_keys WHERE kid=1").fetchone()["public_hex"]


# ---------------- 设备可信：一次性注册码（现场管理员） ----------------

def _clean_device_roles(roles):
    allowed = set(devmod.KNOWN_DEVICE_ROLES)
    if not isinstance(roles, list) or not roles:
        raise EngineError("bad_roles", "必须指定设备可用落款角色", 400)
    out = sorted(set(str(r) for r in roles))
    if any(r not in allowed for r in out):
        raise EngineError("bad_roles", f"存在不支持的设备角色，允许 {sorted(allowed)}", 400)
    return out


def create_register_code(conn, principal, body):
    """现场管理员为本机构签发一次性设备注册码；明文仅本次回显。"""
    if principal["role"] != "site":
        raise EngineError("forbidden", "仅现场负责人可以登记本站设备", 403)
    roles = _clean_device_roles(body.get("roles"))
    minutes = body.get("minutes", 60)
    if not isinstance(minutes, int) or not (1 <= minutes <= 7 * 24 * 60):
        raise EngineError("bad_ttl", "注册码有效期需在 1 分钟到 7 天之间", 400)
    code = secrets.token_urlsafe(18)
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    code_ref = "RC-" + secrets.token_hex(4)
    created = now()
    exp_ms = int(time.time() * 1000) + minutes * 60_000
    begin_tx(conn)
    conn.execute(
        "INSERT INTO register_codes(code_hash,code_ref,inst_id,roles_json,minutes,status,"
        "created_at,expires_at) VALUES(?,?,?,?,?,'open',?,?)",
        (code_hash, code_ref, principal["inst_id"], json.dumps(roles), minutes,
         created, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(exp_ms / 1000))))
    _evt(conn, "register_code_issued", inst_id=principal["inst_id"],
         detail={"code_ref": code_ref, "roles": roles, "minutes": minutes})
    conn.execute("COMMIT")
    return {"code": code, "code_ref": code_ref, "inst_id": principal["inst_id"],
            "roles": roles, "minutes": minutes, "created_at": created}


def list_register_codes(conn, principal):
    if principal["role"] != "site":
        raise EngineError("forbidden", "仅现场负责人可查注册码", 403)
    rows = conn.execute(
        "SELECT code_ref,roles_json,status,created_at,expires_at,used_at,device_id"
        " FROM register_codes WHERE inst_id=? ORDER BY created_at DESC",
        (principal["inst_id"],)).fetchall()
    return [{"code_ref": r["code_ref"], "roles": json.loads(r["roles_json"]),
             "status": r["status"], "created_at": r["created_at"],
             "expires_at": r["expires_at"], "used_at": r["used_at"],
             "device_id": r["device_id"]} for r in rows]


# ---------------- 设备可信：终端首次登记（无登录） ----------------

def register_device(conn, body, now_ms=None):
    """浏览器凭一次性注册码 + 本机公钥 + CSR 自证签名完成登记，服务端签发证书。"""
    now_ms = devmod.now_ms() if now_ms is None else now_ms
    code = str(body.get("code") or "")
    rec = conn.execute(
        "SELECT * FROM register_codes WHERE code_hash=?",
        (hashlib.sha256(code.encode()).hexdigest(),)).fetchone()
    if not rec:
        raise EngineError("register_code_invalid", "注册码无效", 404)
    begin_tx(conn)  # 抢占与登记落盘同一立即写事务
    rec = conn.execute(
        "SELECT * FROM register_codes WHERE code_hash=?",
        (hashlib.sha256(code.encode()).hexdigest(),)).fetchone()
    if rec["status"] == "consumed":
        conn.execute("ROLLBACK")
        raise EngineError("register_code_consumed",
                          "该注册码已成功使用过，不能再次登记", 409)
    if rec["status"] == "revoked":
        conn.execute("ROLLBACK")
        raise EngineError("register_code_invalid", "注册码已作废", 404)
    if int(time.mktime(time.strptime(rec["expires_at"][:19], "%Y-%m-%dT%H:%M:%S")) * 1000) \
            < now_ms:
        conn.execute("ROLLBACK")
        raise EngineError("register_code_expired", "注册码已过期", 410)

    label = str(body.get("device_label") or "").strip()
    if not (1 <= len(label) <= 40):
        conn.execute("ROLLBACK")
        raise EngineError("bad_label", "设备标识为 1–40 字的中性名称", 400)
    public_hex = str(body.get("public_hex") or "")
    if not (len(public_hex) == 64 and all(c in "0123456789abcdef" for c in public_hex)):
        conn.execute("ROLLBACK")
        raise EngineError("bad_public_key", "需要 Ed25519 32 字节小写 hex 公钥", 400)

    # CSR：新私钥对登记请求签名，证明持有与所提交公钥对应的私钥（防公钥冒充）。
    # 被签内容固定为 alg/设备标识/公钥/机构；一次性注册码本身的持有即登记凭证（另查）。
    csr = {
        "alg": "CT-REGISTER-CSR/v1", "code_ref": "",
        "device_label": label, "public_hex": public_hex, "inst_id": rec["inst_id"],
    }
    if not body.get("csr_sig") or not DeviceKey.verify(
            public_hex, canonical_bytes(csr), str(body["csr_sig"])):
        conn.execute("ROLLBACK")
        raise EngineError("csr_sig_invalid", "终端公钥自证签名不合法", 401)

    device_id = "D-" + secrets.token_hex(5)
    cert_id = "C-" + secrets.token_hex(5)
    at_iso = now()
    cert = {
        "cert_id": cert_id, "device_id": device_id, "inst_id": rec["inst_id"],
        "device_label": label, "roles": json.loads(rec["roles_json"]), "gen": 1,
        "not_before_ms": now_ms, "not_after_ms": now_ms + CERT_MINUTES * 60_000,
        "public_hex": public_hex,
    }
    envelope = devmod.issue_certificate(server_key(conn), cert)
    conn.execute(
        "INSERT INTO devices(id,inst_id,device_label,current_cert_id,created_at)"
        " VALUES(?,?,?,?,?)",
        (device_id, rec["inst_id"], label, cert_id, at_iso))
    conn.execute(
        "INSERT INTO device_certs(id,device_id,inst_id,gen,roles_json,public_hex,status,"
        "not_before_ms,not_after_ms,envelope_json,created_at)"
        " VALUES(?,?,?,1,?,?, 'active',?,?,?,?)",
        (cert_id, device_id, rec["inst_id"], json.dumps(cert["roles"]), public_hex,
         cert["not_before_ms"], cert["not_after_ms"],
         json.dumps(envelope, ensure_ascii=False), at_iso))
    conn.execute(
        "UPDATE register_codes SET status='consumed',used_at=?,device_id=? WHERE code_hash=?",
        (at_iso, device_id, rec["code_hash"]))
    _evt(conn, "device_registered", inst_id=rec["inst_id"],
         detail={"device_id": device_id, "cert_id": cert_id,
                 "roles": cert["roles"], "code_ref": rec["code_ref"]})
    conn.execute("COMMIT")
    return {"device_id": device_id, "cert": envelope, "server_time": now()}


# ---------------- 设备可信：隔离 / 轮换 / 查询（现场管理员） ----------------

def _own_device_row(conn, principal, device_id):
    r = conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
    if not r or r["inst_id"] != principal["inst_id"]:
        raise EngineError("device_not_found", "设备不存在或不在本机构", 404)
    return r


def quarantine_device(conn, principal, body):
    if principal["role"] != "site":
        raise EngineError("forbidden", "仅现场负责人可隔离设备", 403)
    d = _own_device_row(conn, principal, str(body.get("device_id") or ""))
    if d["quarantined"]:
        return {"idempotent": True, "device_id": d["id"], "quarantined": True,
                "reason": d["quarantined_reason"], "quarantined_at": d["quarantined_at"]}
    reason = str(body.get("reason") or "").strip()
    if not (1 <= len(reason) <= 100):
        raise EngineError("reason_required", "隔离原因必填且不超过 100 字", 400)
    ts = now()
    begin_tx(conn)
    conn.execute("UPDATE devices SET quarantined=1,quarantined_reason=?,quarantined_at=? WHERE id=?",
                 (reason, ts, d["id"]))
    conn.execute("UPDATE device_certs SET status='quarantined' WHERE device_id=? AND status='active'",
                 (d["id"],))
    _evt(conn, "device_quarantined", inst_id=principal["inst_id"],
         detail={"device_id": d["id"], "reason": reason})
    conn.execute("COMMIT")
    return {"idempotent": False, "device_id": d["id"], "quarantined": True,
            "reason": reason, "quarantined_at": ts}


def list_devices(conn, principal):
    if principal["role"] != "site":
        raise EngineError("forbidden", "仅现场负责人可列设备", 403)
    out = []
    for d in conn.execute("SELECT * FROM devices WHERE inst_id=? ORDER BY created_at",
                         (principal["inst_id"],)):
        certs = conn.execute(
            "SELECT id,gen,roles_json,status,not_after_ms,created_at,rotated_at"
            " FROM device_certs WHERE device_id=? ORDER BY gen", (d["id"],)).fetchall()
        out.append({
            "device_id": d["id"], "device_label": d["device_label"],
            "created_at": d["created_at"], "quarantined": bool(d["quarantined"]),
            "quarantined_reason": d["quarantined_reason"],
            "quarantined_at": d["quarantined_at"], "current_cert_id": d["current_cert_id"],
            "certificates": [{"cert_id": c["id"], "gen": c["gen"],
                              "roles": json.loads(c["roles_json"]), "status": c["status"],
                              "not_after_ms": c["not_after_ms"], "issued_at": c["created_at"],
                              "rotated_at": c["rotated_at"]} for c in certs]})
    return out


def inspect_device(conn, body, now_ms=None):
    """终端持证书自证查询自身状态（任何代次/有效期都可，含被隔离/过期设备）。"""
    now_ms = devmod.now_ms() if now_ms is None else now_ms
    env = body.get("cert")
    if not (isinstance(env, dict) and isinstance(env.get("payload"), dict)
            and isinstance(env.get("signature"), str)):
        raise EngineError("cert_invalid", "终端证书不合法", 400)
    p = env["payload"]
    # 自检只验服务端签发签名，不卡有效期/代次：旧密钥也要能看到自身历史状态
    if p.get("alg") != devmod.TERM_ALG or not devmod.verify_canonical(
            server_public_hex(conn), p, env["signature"]):
        raise EngineError("cert_invalid", "终端证书签名不合法", 400)
    csr = {"alg": "CT-INSPECT/v1", "cert_id": p.get("cert_id"),
           "nonce": str(body.get("nonce") or "")}
    if not body.get("proof_sig") or not DeviceKey.verify(
            str(p.get("public_hex") or ""), canonical_bytes(csr), str(body["proof_sig"])):
        raise EngineError("proof_sig_invalid", "终端自证签名不合法", 401)
    c = conn.execute("SELECT * FROM device_certs WHERE id=?", (p["cert_id"],)).fetchone()
    if not c:
        raise EngineError("cert_unknown", "证书未登记", 404)
    d = conn.execute("SELECT * FROM devices WHERE id=?", (c["device_id"],)).fetchone()
    return {"device_id": d["id"], "cert_id": c["id"], "gen": c["gen"], "status": c["status"],
            "quarantined": bool(d["quarantined"]),
            "quarantined_reason": d["quarantined_reason"],
            "current_cert_id": d["current_cert_id"], "roles": json.loads(c["roles_json"]),
            "within_validity": c["not_after_ms"] > now_ms, "server_time": now()}


def rotate_device(conn, body, now_ms=None):
    """终端持一次性轮换授权 + 新旧双公钥/双签名完成证书代次轮换。"""
    now_ms = devmod.now_ms() if now_ms is None else now_ms
    nonce = str(body.get("rotation_nonce") or "")
    pend = conn.execute("SELECT * FROM rotation_nonces WHERE nonce=?", (nonce,)).fetchone()
    if not pend:
        raise EngineError("rotation_nonce_invalid", "轮换授权码无效", 404)
    if pend["used"]:
        raise EngineError("rotation_nonce_used", "轮换授权码只能使用一次", 409)
    if pend["expires_at_ms"] < now_ms:
        raise EngineError("rotation_nonce_expired", "轮换授权码已过期", 410)
    begin_tx(conn)
    pend = conn.execute("SELECT * FROM rotation_nonces WHERE nonce=?", (nonce,)).fetchone()
    if pend["used"]:
        conn.execute("ROLLBACK")
        raise EngineError("rotation_nonce_used", "轮换授权码只能使用一次", 409)
    old = conn.execute("SELECT * FROM device_certs WHERE id=?", (pend["cert_id"],)).fetchone()
    d = conn.execute("SELECT * FROM devices WHERE id=?", (pend["device_id"],)).fetchone()
    if d["quarantined"] or old["status"] != "active":
        conn.execute("ROLLBACK")
        raise EngineError("cert_not_active", "证书当前不可轮换", 409)
    new_hex = str(body.get("new_public_hex") or "")
    if not (len(new_hex) == 64 and all(c in "0123456789abcdef" for c in new_hex)):
        conn.execute("ROLLBACK")
        raise EngineError("bad_public_key", "需要 Ed25519 32 字节小写 hex 公钥", 400)
    csr = {"alg": "CT-ROTATION-CSR/v1", "rotation_nonce": nonce,
           "old_cert_id": old["id"], "device_id": d["id"], "new_public_hex": new_hex}
    if not body.get("new_sig") or not DeviceKey.verify(
            new_hex, canonical_bytes(csr), str(body["new_sig"])) \
            or not body.get("old_sig") or not DeviceKey.verify(
                old["public_hex"], canonical_bytes(csr), str(body["old_sig"])):
        conn.execute("ROLLBACK")
        raise EngineError("rotation_sig_invalid", "必须同时用旧私钥与新私钥对轮换请求签名", 401)
    new_id = "C-" + secrets.token_hex(5)
    roles = json.loads(old["roles_json"])
    cert = {"cert_id": new_id, "device_id": d["id"], "inst_id": d["inst_id"],
            "device_label": d["device_label"], "roles": roles, "gen": old["gen"] + 1,
            "not_before_ms": now_ms, "not_after_ms": now_ms + CERT_MINUTES * 60_000,
            "public_hex": new_hex}
    envelope = devmod.issue_certificate(server_key(conn), cert)
    ts = now()
    conn.execute("UPDATE device_certs SET status='rotated',rotated_at=? WHERE id=?",
                 (ts, old["id"]))
    conn.execute(
        "INSERT INTO device_certs(id,device_id,inst_id,gen,roles_json,public_hex,status,"
        "not_before_ms,not_after_ms,envelope_json,created_at)"
        " VALUES(?,?,?,?,?,?,'active',?,?,?,?)",
        (new_id, d["id"], d["inst_id"], old["gen"] + 1, json.dumps(roles), new_hex,
         cert["not_before_ms"], cert["not_after_ms"],
         json.dumps(envelope, ensure_ascii=False), ts))
    conn.execute("UPDATE devices SET current_cert_id=? WHERE id=?", (new_id, d["id"]))
    conn.execute("UPDATE rotation_nonces SET used=1,used_at=? WHERE nonce=?", (ts, nonce))
    _evt(conn, "certificate_rotated", inst_id=d["inst_id"],
         detail={"device_id": d["id"], "old_cert_id": old["id"], "cert_id": new_id,
                 "gen": old["gen"] + 1})
    conn.execute("COMMIT")
    return {"device_id": d["id"], "cert": envelope, "old_cert_id": old["id"],
            "gen": old["gen"] + 1}


def prepare_rotation(conn, principal, body):
    """现场管理员为本站在用证书签发一次性短时轮换授权码。"""
    if principal["role"] != "site":
        raise EngineError("forbidden", "仅现场负责人可发起轮换", 403)
    cert_id = str(body.get("cert_id") or "")
    row = conn.execute("SELECT * FROM device_certs WHERE id=?", (cert_id,)).fetchone()
    d = row and conn.execute("SELECT * FROM devices WHERE id=?", (row["device_id"],)).fetchone()
    if not row or not d or d["inst_id"] != principal["inst_id"]:
        raise EngineError("cert_not_found", "证书不存在或不在本机构", 404)
    if d["quarantined"] or row["status"] != "active":
        raise EngineError("cert_not_active", "只有当前在用证书可以轮换", 409)
    nonce = secrets.token_urlsafe(18)
    exp = devmod.now_ms() + 10 * 60_000
    begin_tx(conn)
    conn.execute(
        "INSERT INTO rotation_nonces(nonce,cert_id,device_id,expires_at_ms,created_at)"
        " VALUES(?,?,?,?,?)",
        (nonce, row["id"], d["id"], exp, now()))
    _evt(conn, "rotation_prepared", inst_id=principal["inst_id"],
         detail={"device_id": d["id"], "cert_id": row["id"], "gen": row["gen"]})
    conn.execute("COMMIT")
    return {"rotation_nonce": nonce, "cert_id": row["id"], "device_id": d["id"],
            "gen": row["gen"], "expires_at_ms": exp}


def list_device_audit(conn, principal, *, device_id=None, limit=200):
    """现场查看本站设备凭据流水（设备审计）：每条状态变更都对应一条凭据。"""
    if principal["role"] != "site":
        raise EngineError("forbidden", "仅现场负责人可查设备审计", 403)
    sql = ("SELECT id,nonce,cert_id,device_id,inst_id,action,session_id,role,request_fp,"
           "outcome,record_ref,created_at FROM device_attestations WHERE inst_id=?")
    args = [principal["inst_id"]]
    if device_id:
        d = _own_device_row(conn, principal, str(device_id))
        sql += " AND device_id=?"; args.append(d["id"])
    sql += " ORDER BY id DESC LIMIT ?"; args.append(int(limit))
    return [dict(r) for r in conn.execute(sql, args)]


# ---------------- 设备可信：挑战网关 ----------------

def issue_challenge(conn, body, now_ms=None):
    """领取短时挑战。只有 active/未隔离/当前代次、机构匹配、角色覆盖的证书可领。

    挑战钉死 action/session_id/role/body_digest/inst_id/截止时间，提交时逐字比对，
    调换机构或会话、调换角色或内容指纹都稳定失败。
    """
    now_ms = devmod.now_ms() if now_ms is None else now_ms
    p = devmod.parse_certificate(body.get("cert"), server_public_hex(conn), now_ms)
    if not p:
        raise EngineError("cert_invalid", "终端证书签名非法或已过有效期", 400)
    cert = conn.execute("SELECT * FROM device_certs WHERE id=?", (p["cert_id"],)).fetchone()
    if not cert:
        raise EngineError("cert_unknown", "证书未登记", 404)
    d = conn.execute("SELECT * FROM devices WHERE id=?", (cert["device_id"],)).fetchone()
    if d["quarantined"] or cert["status"] == "quarantined":
        raise EngineError("device_quarantined", "设备已被隔离，不能领取挑战", 403)
    if cert["status"] == "rotated" or d["current_cert_id"] != cert["id"]:
        raise EngineError("cert_rotated", "旧证书代次已轮换，不能领取新挑战", 403)

    action = str(body.get("action") or "")
    if action not in devmod.ACTION_ROLES:
        raise EngineError("action_unknown", "业务动作不在目录内", 400)
    role = str(body.get("role") or "")
    cert_roles = set(json.loads(cert["roles_json"]))
    if role not in devmod.ACTION_ROLES[action] or not any(
            devmod.device_role_may_sign(dr, role) for dr in cert_roles):
        raise EngineError("role_not_allowed",
                          "该角色不能对此动作落款或证书未授予此角色", 403)
    session_id = body.get("session_id")
    if session_id is not None:
        session_id = str(session_id)
        if not session_id:
            raise EngineError("bad_session", "会话标识不能为空", 400)
    inst_id = str(body.get("inst_id") or cert["inst_id"])
    if inst_id != cert["inst_id"]:
        raise EngineError("site_mismatch", "请求机构与证书机构不一致", 409)
    body_digest = str(body.get("body_digest") or "")
    if not (len(body_digest) == 64 and all(c in "0123456789abcdef" for c in body_digest)):
        raise EngineError("bad_digest", "内容指纹需为 64 位十六进制 SHA-256", 400)

    nonce = secrets.token_hex(16)
    ch = {"cert_id": cert["id"], "nonce": nonce, "action": action,
          "session_id": session_id, "role": role, "body_digest": body_digest,
          "inst_id": inst_id, "not_before_ms": now_ms,
          "not_after_ms": now_ms + CHALLENGE_TTL_MS}
    token = devmod.issue_challenge(server_key(conn), ch)
    conn.execute(
        "INSERT INTO challenges(nonce,cert_id,inst_id,action,session_id,role,body_digest,"
        "not_before_ms,not_after_ms,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (nonce, cert["id"], inst_id, action, session_id, role, body_digest,
         now_ms, ch["not_after_ms"], now()))
    return token


def _err_reject(conn, code, message, http=400, *, inst_id=None, cert_id=None, action=None):
    """失败也要留痕（设备审计可说明被拒绝原因），但不消费随机数、不产生业务变更。"""
    try:
        detail = {"reason": code}
        if cert_id:
            detail["cert_id"] = cert_id
        if action:
            detail["action"] = action
        _evt(conn, "request_rejected", inst_id=inst_id, detail=detail)
    except Exception:
        pass
    raise EngineError(code, message, http)


def verify_attestation(conn, body, *, now_ms=None):
    """在调用方已开启的 BEGIN IMMEDIATE 事务内**只做**设备证明核验，不落任何状态。

    返回 att 凭据上下文（replay=True 表示同载荷重试）。核验顺序：证书链/有效期 →
    挑战签名/时间窗 → 六+一绑定字段逐字比对 → 动作角色授权 → 终端私钥签名 →
    挑战在册 → 设备当前未隔离/证书为当前代次 → 随机数是否已消费。

    关键：随机数的**占用**（写 device_attestations）由 consume_attestation 在业务前置
    校验全部通过、确实要产生状态变更时才执行，因此竞争落败（他人占槽/已完成/已撤销/
    已执行）的请求会整体回滚，既不产生业务变更，也不在设备审计中留下虚假凭据。
    """
    now_ms = devmod.now_ms() if now_ms is None else now_ms
    spub = server_public_hex(conn)

    # 1) 证书链 + 有效期
    p = devmod.parse_certificate(body.get("cert"), spub, now_ms)
    if not p:
        _err_reject(conn, "cert_invalid", "终端证书签名非法或已过有效期", 400)
    cert = conn.execute("SELECT * FROM device_certs WHERE id=?", (p["cert_id"],)).fetchone()
    if not cert:
        _err_reject(conn, "cert_unknown", "证书未登记", 400, cert_id=p["cert_id"])
    d = conn.execute("SELECT * FROM devices WHERE id=?", (cert["device_id"],)).fetchone()

    # 2) 挑战服务端签名 + 时间窗
    ch = body.get("challenge")
    ch_sig = body.get("challenge_sig")
    if not isinstance(ch, dict) or not ch_sig or not devmod.verify_canonical(
            spub, ch, str(ch_sig)):
        _err_reject(conn, "challenge_bad_sig", "挑战签名不合法", 401,
                    inst_id=cert["inst_id"], cert_id=cert["id"], action=ch.get("action")
                    if isinstance(ch, dict) else None)
    if int(ch["not_after_ms"]) <= now_ms or int(ch["not_before_ms"]) > now_ms:
        _err_reject(conn, "challenge_expired", "挑战已过期，请重新领取", 410,
                    inst_id=cert["inst_id"], cert_id=cert["id"], action=ch["action"])

    # 3) 挑战绑定字段逐字比对（调换机构/会话/角色/内容指纹/随机数/证书任一即拒）
    bound = ["cert_id", "nonce", "action", "session_id", "role", "body_digest", "inst_id"]
    for f in bound:
        if str(body.get(f) if body.get(f) is not None else "") != \
                str(ch.get(f) if ch.get(f) is not None else ""):
            _err_reject(conn, "request_fields_replaced",
                        f"请求与挑战绑定不一致（{f}），拒绝变更", 409,
                        inst_id=cert["inst_id"], cert_id=cert["id"], action=ch["action"])
    if ch["cert_id"] != cert["id"]:
        _err_reject(conn, "request_fields_replaced", "证书与挑战不匹配", 409,
                    inst_id=cert["inst_id"], cert_id=cert["id"], action=ch["action"])
    action = ch["action"]
    role = ch["role"]
    if action not in devmod.ACTION_ROLES or role not in devmod.ACTION_ROLES[action]:
        _err_reject(conn, "role_not_allowed", "动作或角色不允许", 403,
                    inst_id=cert["inst_id"], cert_id=cert["id"], action=action)
    if not any(devmod.device_role_may_sign(dr, role)
               for dr in json.loads(cert["roles_json"])):
        _err_reject(conn, "role_not_allowed", "证书未授予该落款角色", 403,
                    inst_id=cert["inst_id"], cert_id=cert["id"], action=action)

    # 4) 终端私钥对完整请求的签名（必须持有本机私钥）
    flat = {**ch, "challenge_sig": str(ch_sig)}
    sreq = devmod.signing_request(flat)
    if not body.get("terminal_sig") or not DeviceKey.verify(
            cert["public_hex"], canonical_bytes(sreq), str(body["terminal_sig"])):
        _err_reject(conn, "terminal_sig_invalid", "终端签名核验失败", 401,
                    inst_id=cert["inst_id"], cert_id=cert["id"], action=action)

    # 5) 挑战确由本服务签发且仍登记（防止拿自造/已抹除挑战重放）
    ch_row = conn.execute("SELECT * FROM challenges WHERE nonce=?", (ch["nonce"],)).fetchone()
    if not ch_row:
        _err_reject(conn, "challenge_unknown", "挑战未登记或已失效", 410,
                    inst_id=cert["inst_id"], cert_id=cert["id"], action=action)

    # 6) 设备当前资格：隔离 / 旧代一律拒（在同一事务按最新持久化状态判定）
    if d["quarantined"] or cert["status"] == "quarantined":
        _err_reject(conn, "device_quarantined", "设备已被隔离，失去操作资格", 403,
                    inst_id=cert["inst_id"], cert_id=cert["id"], action=action)
    if cert["status"] == "rotated" or d["current_cert_id"] != cert["id"]:
        _err_reject(conn, "cert_rotated", "该证书代次已轮换，旧密钥只能核对历史", 403,
                    inst_id=cert["inst_id"], cert_id=cert["id"], action=action)

    fp = devmod.request_fingerprint(sreq)
    att = {"replay": False, "att_id": None, "fp": fp, "cert_id": cert["id"],
           "device_id": d["id"], "inst_id": cert["inst_id"], "action": action,
           "session_id": ch["session_id"], "role": role, "nonce": ch["nonce"],
           "terminal_sig": str(body["terminal_sig"]), "challenge_sig": str(ch_sig)}

    # 7) 随机数重放：已消费且同载荷=同载荷重试，交调用方复用首次回执；异文=拒绝。
    prior = conn.execute(
        "SELECT id,request_fp,outcome,record_ref FROM device_attestations WHERE nonce=?",
        (ch["nonce"],)).fetchone()
    if prior:
        if prior["request_fp"] != fp:
            _err_reject(conn, "nonce_reused",
                        "该挑战随机数已使用，不能用它换取第二个结果", 409,
                        inst_id=cert["inst_id"], cert_id=cert["id"], action=action)
        att.update(replay=True, att_id=prior["id"], outcome=prior["outcome"],
                   record_ref=prior["record_ref"])
    return att


def consume_attestation(conn, att):
    """业务前置校验全部通过后，原子占用随机数并写凭据行。

    必须与业务 INSERT/UPDATE 在同一 BEGIN IMMEDIATE 事务：UNIQUE(nonce) 在最底层保证，
    并发两终端只有一个 INSERT 成功（另一个抛 IntegrityError → slot 冲突），提交则凭据与
    变更同时成立；若之后任何一步失败或进程崩溃，事务整体回滚，不留半边成功。
    返回 att_id。
    """
    cur = conn.execute(
        "INSERT INTO device_attestations(nonce,cert_id,device_id,inst_id,action,session_id,"
        "role,request_fp,terminal_sig,challenge_sig,target,outcome,record_ref,created_at)"
        " VALUES(?,?,?,?,?,?,?,?,?,?, '', '', '', ?)",
        (att["nonce"], att["cert_id"], att["device_id"], att["inst_id"], att["action"],
         att["session_id"], att["role"], att["fp"], att["terminal_sig"],
         att["challenge_sig"], now()))
    att["att_id"] = cur.lastrowid
    return cur.lastrowid


def _finalize_attestation(conn, att, *, target, outcome, record_ref):
    """业务结论落定后回填凭据行（与业务变更在同一事务提交）。"""
    conn.execute(
        "UPDATE device_attestations SET target=?,outcome=?,record_ref=? WHERE id=?",
        (target, outcome, record_ref, att["att_id"]))


def _consume_and_finalize(conn, att, *, target, outcome, record_ref):
    """占用随机数写凭据行并立即回填结论（用于"无后续 INSERT 的纯状态变更"分支）。"""
    consume_attestation(conn, att)
    _finalize_attestation(conn, att, target=target, outcome=outcome, record_ref=record_ref)
    return att["att_id"]


# ---------------- 材料发布 / 停用 ----------------

def publish_material(conn, *, family, inst_id, language, body, conditions, roles,
                     scope, requires_reconsent=False, reconsent_ops=None, principal=None):
    if principal and principal["role"] != "admin":
        raise EngineError("forbidden", "只有规则维护员可以发布材料", 403)
    if not family or not body:
        raise EngineError("bad_material", "family 与正文不能为空")
    inst = conn.execute("SELECT id FROM institutions WHERE id=?", (inst_id,)).fetchone()
    if not inst:
        raise EngineError("inst_not_found", "机构不存在", 404)
    roles = list(roles or [])
    if not roles or "subject" not in roles or "site_owner" not in roles:
        raise EngineError("bad_roles", "必签角色至少包含参与人与现场负责人")
    if any(r not in KNOWN_ROLES for r in roles):
        raise EngineError("bad_roles", f"未知角色，允许 {KNOWN_ROLES}")
    scope = list(scope or [])
    if not scope:
        raise EngineError("bad_scope", "至少允许一项操作")
    if any(op not in KNOWN_OPS for op in scope):
        raise EngineError("bad_scope", f"未知操作，允许 {KNOWN_OPS}")
    conditions = dict(conditions or {})
    reconsent_ops = list(reconsent_ops or [])
    if requires_reconsent and not reconsent_ops:
        raise EngineError("bad_reconsent", "要求再次同意时必须给出受影响操作")
    if any(op not in scope for op in reconsent_ops):
        raise EngineError("bad_reconsent", "再次同意的操作必须在本版许可范围内")

    tk = track_key(family, inst_id, language, conditions)
    bh = seal_body(body, inst_id, language, conditions, roles, scope)

    begin_tx(conn)
    latest = conn.execute(
        "SELECT * FROM materials WHERE track_key=? ORDER BY version DESC LIMIT 1", (tk,)).fetchone()
    if latest and latest["body_hash"] == bh and latest["scope_json"] == json.dumps(
            scope, ensure_ascii=False) and bool(latest["requires_reconsent"]) == bool(requires_reconsent) \
            and latest["reconsent_ops_json"] == json.dumps(reconsent_ops, ensure_ascii=False):
        conn.execute("ROLLBACK")
        raise EngineError("unchanged_version", "正文与覆盖范围均无变化，无需另立版本", 409)

    version = (latest["version"] + 1) if latest else 1
    cur = conn.execute(
        "INSERT INTO materials(family,version,inst_id,language,body,conditions_json,roles_json,"
        "scope_json,requires_reconsent,reconsent_ops_json,status,track_key,body_hash,published_at)"
        " VALUES(?,?,?,?,?,?,?,?,?,?, 'active', ?,?,?)",
        (family, version, inst_id, language, body,
         json.dumps(conditions, ensure_ascii=False), json.dumps(sorted(roles), ensure_ascii=False),
         json.dumps(scope, ensure_ascii=False), 1 if requires_reconsent else 0,
         json.dumps(reconsent_ops, ensure_ascii=False), tk, bh, now()),
    )
    mid = cur.lastrowid
    _evt(conn, "material_published", inst_id=inst_id, material_id=mid, detail={
        "family": family, "version": version, "language": language,
        "conditions": conditions, "roles": sorted(roles), "scope": scope,
        "requires_reconsent": bool(requires_reconsent), "reconsent_ops": reconsent_ops,
        "body_hash": bh, "track_key": tk,
    })
    conn.execute("COMMIT")
    return get_material(conn, mid)


def retire_material(conn, material_id, principal=None):
    if principal and principal["role"] != "admin":
        raise EngineError("forbidden", "只有规则维护员可以停用材料", 403)
    begin_tx(conn)
    m = conn.execute("SELECT * FROM materials WHERE id=?", (material_id,)).fetchone()
    if not m:
        conn.execute("ROLLBACK")
        raise EngineError("material_not_found", "材料不存在", 404)
    if m["status"] == "retired":
        conn.execute("ROLLBACK")
        raise EngineError("already_retired", "材料已停用", 409)
    ts = now()
    conn.execute("UPDATE materials SET status='retired',retired_at=? WHERE id=?", (ts, material_id))
    # 办理途中停用：未结束会话立刻冻结，不能悄悄降级/挪到别的版本
    rows = conn.execute(
        "SELECT id,subject_id FROM sessions WHERE material_id=? AND status='open'",
        (material_id,)).fetchall()
    for r in rows:
        conn.execute("UPDATE sessions SET status='blocked',blocked_at=? WHERE id=?", (ts, r["id"]))
        _evt(conn, "session_blocked", inst_id=m["inst_id"], subject_id=r["subject_id"],
             session_id=r["id"], material_id=material_id,
             detail={"reason": "material_retired", "version": m["version"]})
    _evt(conn, "material_retired", inst_id=m["inst_id"], material_id=material_id,
         detail={"family": m["family"], "version": m["version"], "blocked_sessions": len(rows)})
    conn.execute("COMMIT")
    return get_material(conn, material_id)


def get_material(conn, mid):
    r = conn.execute("SELECT * FROM materials WHERE id=?", (mid,)).fetchone()
    if not r:
        raise EngineError("material_not_found", "材料不存在", 404)
    return _material_dict(r)


def _material_dict(r):
    return {
        "id": r["id"], "family": r["family"], "version": r["version"],
        "inst_id": r["inst_id"], "language": r["language"], "body": r["body"],
        "conditions": _j(r, "conditions_json", {}), "roles": _j(r, "roles_json", []),
        "scope": _j(r, "scope_json", []),
        "requires_reconsent": bool(r["requires_reconsent"]),
        "reconsent_ops": _j(r, "reconsent_ops_json", []),
        "status": r["status"], "track_key": r["track_key"], "body_hash": r["body_hash"],
        "published_at": r["published_at"], "retired_at": r["retired_at"],
    }


def list_materials(conn, *, inst_id=None, family=None, include_retired=False):
    sql = "SELECT * FROM materials WHERE 1=1"
    args = []
    if not include_retired:
        sql += " AND status='active'"
    if inst_id:
        sql += " AND inst_id=?"; args.append(inst_id)
    if family:
        sql += " AND family=?"; args.append(family)
    sql += " ORDER BY family, inst_id, language, version"
    return [_material_dict(r) for r in conn.execute(sql, args)]


def _conditions_match(mat_cond, subj_cond):
    return all(subj_cond.get(k) == v for k, v in mat_cond.items())


def eligibility_for_subject(conn, subject):
    """现场开单时只能选 机构+语种+人群条件 全部吻合 的现行版材料。"""
    out = []
    mats = [m for m in list_materials(conn, inst_id=subject["inst_id"])
            if m["language"] == subject["language"]]
    # 每个 track 只呈现最新版（不允许拿旧版/未批准译文拼接）
    latest = {}
    for m in mats:
        latest[m["track_key"]] = m
    for m in latest.values():
        reasons = []
        if m["language"] != subject.get("language"):
            reasons.append("language_mismatch")
        if not _conditions_match(m["conditions"], subject["conditions"]):
            reasons.append("condition_mismatch")
        out.append({**m, "eligible": not reasons, "reject_reasons": reasons})
    return sorted(out, key=lambda m: (m["family"], m["track_key"]))


# ---------------- 签署会话 ----------------

def _new_token():
    return secrets.token_urlsafe(18)


def start_session(conn, subject_id, material_id, principal=None):
    subj = get_subject(conn, subject_id)
    if principal:
        if principal["role"] == "admin":
            raise EngineError("forbidden", "规则维护员不能替人办理落款", 403)
        if principal["role"] == "site" and principal["inst_id"] != subj["inst_id"]:
            raise EngineError("cross_institution", "资源不属于本机构", 404)
    m = get_material(conn, material_id)
    if m["inst_id"] != subj["inst_id"]:
        raise EngineError("cross_institution", "资源不属于本机构", 404)
    if m["status"] != "active":
        raise EngineError("material_retired", "材料已停用，不能开新会话", 409)
    if m["language"] != subj.get("language"):
        raise EngineError("language_mismatch", "首选语种与材料语种不一致", 409)
    if not _conditions_match(m["conditions"], subj["conditions"]):
        raise EngineError("condition_mismatch", "人群条件不吻合", 409)

    begin_tx(conn)
    dup = conn.execute(
        "SELECT * FROM sessions WHERE subject_id=? AND track_key=? AND status='open'",
        (subject_id, m["track_key"])).fetchone()
    if dup:
        conn.execute("ROLLBACK")
        return get_session(conn, dup["id"], principal)
    sid = "S-" + secrets.token_hex(6)
    conn.execute(
        "INSERT INTO sessions(id,subject_id,material_id,track_key,status,created_at)"
        " VALUES(?,?,?,?,'open',?)",
        (sid, subject_id, m["id"], m["track_key"], now()))
    tokens = {}
    for role in m["roles"]:
        tok = _new_token()
        conn.execute(
            "INSERT INTO sign_slots(session_id,role,token_hash) VALUES(?,?,?)",
            (sid, role, hashlib.sha256(tok.encode()).hexdigest()))
        tokens[role] = tok
    _evt(conn, "session_started", inst_id=subj["inst_id"], subject_id=subject_id,
         session_id=sid, material_id=m["id"],
         detail={"family": m["family"], "version": m["version"], "track_key": m["track_key"],
                 "body_hash": m["body_hash"]})
    conn.execute("COMMIT")
    s = get_session(conn, sid, principal)
    s["slot_tokens"] = tokens  # 仅本次开单返回；现场可另行索取未用令牌
    return s


def _session_views(conn, rows):
    out = []
    for r in rows:
        m = conn.execute("SELECT * FROM materials WHERE id=?", (r["material_id"],)).fetchone()
        sigs = conn.execute("SELECT role,signer_name,created_at,body_hash FROM signatures WHERE session_id=?",
                            (r["id"],)).fetchall()
        slots = []
        for sl in conn.execute("SELECT * FROM sign_slots WHERE session_id=? ORDER BY id", (r["id"],)):
            sg = next((s for s in sigs if s["role"] == sl["role"]), None)
            slots.append({"role": sl["role"], "role_label": ROLE_LABELS[sl["role"]],
                          "filled": sg is not None,
                          "signer_name": sg["signer_name"] if sg else None,
                          "signed_at": sg["created_at"] if sg else None})
        out.append({
            "id": r["id"], "status": r["status"], "subject_id": r["subject_id"],
            "material_id": r["material_id"], "track_key": r["track_key"],
            "created_at": r["created_at"], "completed_at": r["completed_at"],
            "withdrawn_at": r["withdrawn_at"], "blocked_at": r["blocked_at"],
            "material": _material_dict(m),
            "slots": slots,
            "remaining_roles": [s["role"] for s in slots if not s["filled"]],
        })
    return out


def get_session(conn, session_id, principal=None):
    r = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
    if not r:
        raise EngineError("session_not_found", "会话不存在", 404)
    view = _session_views(conn, [r])[0]
    subj = get_subject(conn, view["subject_id"])
    if principal:
        if principal["role"] == "site" and principal["inst_id"] != subj["inst_id"]:
            # 跨机构：对其他机构统一报“不存在”，报错不暴露他人身份
            raise EngineError("session_not_found", "会话不存在", 404)
        if principal["role"] == "subject":
            linked = conn.execute("SELECT id FROM subjects WHERE user_id=?",
                                  (principal["id"],)).fetchone()
            if not linked or linked["id"] != view["subject_id"]:
                raise EngineError("session_not_found", "会话不存在", 404)
    return view


def list_sessions(conn, *, subject_id=None, inst_id=None):
    sql = "SELECT * FROM sessions WHERE 1=1"
    args = []
    if subject_id:
        sql += " AND subject_id=?"; args.append(subject_id)
    if inst_id:
        sql += " AND subject_id IN (SELECT id FROM subjects WHERE inst_id=?)"
        args.append(inst_id)
    sql += " ORDER BY created_at DESC"
    return _session_views(conn, conn.execute(sql, args).fetchall())


def slot_tokens(conn, session_id, principal):
    """现场负责人获取未签角色的一次性签名链接（见证者等）。"""
    s = get_session(conn, session_id, principal)
    if principal["role"] != "site":
        raise EngineError("forbidden", "仅现场人员可以索取签名令牌", 403)
    out = {}
    regenerated = False
    for sl in conn.execute("SELECT role,token_hash FROM sign_slots WHERE session_id=?",
                           (session_id,)).fetchall():
        if sl["role"] != "subject" and sl["token_hash"]:
            sig = conn.execute("SELECT 1 FROM signatures WHERE session_id=? AND role=?",
                               (session_id, sl["role"])).fetchone()
            if not sig:
                # 无法反推明文令牌：未使用时重置一个新的，旧链接自然失效
                tok = _new_token()
                if not regenerated:
                    begin_tx(conn)
                    regenerated = True
                conn.execute("UPDATE sign_slots SET token_hash=? WHERE session_id=? AND role=?",
                             (hashlib.sha256(tok.encode()).hexdigest(), session_id, sl["role"]))
                out[sl["role"]] = tok
    if regenerated:
        conn.execute("COMMIT")
    return {"session_id": session_id, "tokens": out}


def sign(conn, session_id, role, *, signer_name=None, token=None, principal=None,
         idem_key=None, attestation=None):
    scope = f"sign:{session_id}:{role}"
    if idem_key:
        hit = _idem_get(conn, idem_key, scope)
        if hit:
            code, body, _ = hit
            body["replayed"] = True
            return code, body

    begin_tx(conn)
    # —— 设备证明核验（只验证、不落状态）与业务落盘在同一立即写事务内。
    if attestation is None:
        conn.execute("ROLLBACK")
        raise EngineError("device_attestation_required",
                          "本入口的状态变更必须绑定本站有效设备证明", 401)
    att = verify_attestation(conn, attestation)
    if att["action"] != "sign" or att["session_id"] != session_id or att["role"] != role:
        conn.execute("ROLLBACK")
        raise EngineError("request_fields_replaced", "设备证明与本次落款不一致", 409)

    if att["replay"]:
        # 同载荷重试：复用首个回执（不产生第二次签名/第二次变更）
        conn.execute("ROLLBACK")
        view = get_session(conn, session_id, principal)
        return 200, {"result": "already_signed", "replayed": True, "session": view,
                     "attest_nonce": att["nonce"], "first_attestation_id": att["att_id"]}

    r = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
    if not r:
        conn.execute("ROLLBACK")
        raise EngineError("session_not_found", "会话不存在", 404)
    subj = get_subject(conn, r["subject_id"])
    m = conn.execute("SELECT * FROM materials WHERE id=?", (r["material_id"],)).fetchone()
    if att["inst_id"] != subj["inst_id"]:
        conn.execute("ROLLBACK")
        raise EngineError("site_mismatch", "设备不属于本机构，拒绝变更", 409)

    # 权限与身份核对
    if role not in KNOWN_ROLES:
        conn.execute("ROLLBACK")
        raise EngineError("bad_role", "未知签署角色")
    slot = conn.execute("SELECT * FROM sign_slots WHERE session_id=? AND role=?",
                        (session_id, role)).fetchone()
    if not slot:
        conn.execute("ROLLBACK")
        raise EngineError("role_not_required", "这份封存材料不要求该角色签署", 409)

    signer_principal = None
    if role == "witness":
        if not token or not signer_name:
            conn.execute("ROLLBACK")
            raise EngineError("witness_token_required", "见证者需凭一次性签名链接并署名", 403)
        if slot["token_used"] or hashlib.sha256(token.encode()).hexdigest() != slot["token_hash"]:
            conn.execute("ROLLBACK")
            raise EngineError("invalid_token", "签名链接无效或已使用", 403)
        signer_principal = "witness:token"
    else:
        if not principal:
            conn.execute("ROLLBACK")
            raise EngineError("login_required", "该角色必须登录后签署", 401)
        if principal["role"] == "admin":
            conn.execute("ROLLBACK")
            raise EngineError("forbidden", "规则维护员不得替人落款", 403)
        if role == "subject":
            if principal["role"] != "subject":
                conn.execute("ROLLBACK")
                raise EngineError("forbidden", "只有参与人本人能签参与人栏", 403)
            linked = conn.execute("SELECT id FROM subjects WHERE user_id=?",
                                  (principal["id"],)).fetchone()
            if not linked or linked["id"] != r["subject_id"]:
                conn.execute("ROLLBACK")
                raise EngineError("session_not_found", "会话不存在", 404)
            signer_principal = principal["id"]
            signer_name = principal["name"]
        elif role == "site_owner":
            if principal["role"] != "site" or principal["inst_id"] != subj["inst_id"]:
                conn.execute("ROLLBACK")
                raise EngineError("forbidden", "必须由本机构现场负责人签署", 403)
            signer_principal = principal["id"]
            signer_name = principal["name"]

    # 目标槽位冲突优先判定：两个终端并发抢同一槽位时，先持久化者占槽，
    # 后者稳定收到 slot_filled_by_other（即使前者恰好在本事务前把会话补齐为 completed）。
    # 此处尚未占用随机数，冲突/重复都不会在设备审计中留下凭据。
    sig_hash = hashlib.sha256(
        f"{session_id}|{role}|{signer_principal}|{m['body_hash']}".encode()).hexdigest()
    existing = conn.execute("SELECT * FROM signatures WHERE slot_id=?", (slot["id"],)).fetchone()
    if existing:
        conn.execute("ROLLBACK")
        if existing["signer_principal"] != signer_principal:
            raise EngineError(
                "slot_filled_by_other",
                f"{ROLE_LABELS[role]}签署位已由 {existing['signer_name']} 完成，不能重复落款",
                409)
        view = get_session(conn, session_id, principal)
        body = {"result": "already_signed", "session": view,
                "first_signed_at": existing["created_at"]}
        if idem_key:
            begin_tx(conn); _idem_put(conn, idem_key, scope, 200, body); conn.execute("COMMIT")
        return 200, body

    # 会话状态（与撤销、停用竞争时以本事务内读到的持久化状态为准）
    if r["status"] == "blocked" or m["status"] == "retired":
        if r["status"] == "open":
            ts0 = now()
            conn.execute("UPDATE sessions SET status='blocked',blocked_at=? WHERE id=?",
                         (ts0, session_id))
            _evt(conn, "session_blocked", inst_id=subj["inst_id"], subject_id=subj["id"],
                 session_id=session_id, material_id=m["id"],
                 detail={"reason": "material_retired", "version": m["version"]})
            # 材料停用导致的冻结是一个真实状态变更：凭据随之成立
            _consume_and_finalize(conn, att, target=session_id, outcome="blocked", record_ref=None)
            conn.execute("COMMIT")
        else:
            conn.execute("ROLLBACK")
        raise EngineError("material_retired", "材料在签署途中被停用，本会话已冻结", 409)
    if r["status"] == "withdrawn":
        conn.execute("ROLLBACK")
        raise EngineError("session_withdrawn", "参与人已撤销，不能再落款", 409)
    if r["status"] == "completed":
        # 槽位本身尚无签名却已完成（理论上不会发生）：稳定拒绝、不留凭据
        conn.execute("ROLLBACK")
        raise EngineError("already_completed", "所有必需角色已完成签署", 409)

    # —— 前置校验全部通过、确实要产生变更：此刻原子占用随机数并写凭据行。
    #    与下方签名 INSERT/许可在同一事务：并发下 UNIQUE(nonce) 兜底，只有一笔成功。
    consume_attestation(conn, att)
    ts = now()
    cur = conn.execute(
        "INSERT INTO signatures(session_id,slot_id,role,signer_principal,signer_name,"
        "body_hash,sig_hash,created_at,device_id,cert_id,attest_nonce)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (session_id, slot["id"], role, signer_principal, signer_name,
         m["body_hash"], sig_hash, ts, att["device_id"], att["cert_id"], att["nonce"]))
    if role == "witness":
        conn.execute("UPDATE sign_slots SET token_used=1,signer_name=? WHERE id=?",
                     (signer_name, slot["id"]))
    else:
        conn.execute("UPDATE sign_slots SET signer_name=? WHERE id=?", (signer_name, slot["id"]))
    _evt(conn, "signed", inst_id=subj["inst_id"], subject_id=subj["id"],
         session_id=session_id, material_id=m["id"],
         detail={"role": role, "signer_name": signer_name, "body_hash": m["body_hash"],
                 "version": m["version"], "device_id": att["device_id"],
                 "cert_id": att["cert_id"], "attest_nonce": att["nonce"]})

    body = {"result": "signed", "role": role, "signed_at": ts, "attest_nonce": att["nonce"]}
    outcome = "signed"
    record_ref = str(cur.lastrowid)
    # 全部必签角色针对同一份封存内容完成 -> 生成唯一有效许可
    unfilled = conn.execute(
        "SELECT sl.role FROM sign_slots sl LEFT JOIN signatures sg ON sg.slot_id=sl.id"
        " WHERE sl.session_id=? AND sg.id IS NULL", (session_id,)).fetchall()
    if not unfilled:
        conn.execute("UPDATE sessions SET status='completed',completed_at=? WHERE id=?",
                     (ts, session_id))
        seq = conn.execute("SELECT COALESCE(MAX(seq),0)+1 AS n FROM events").fetchone()["n"]
        permit_id = "P-" + secrets.token_hex(6)
        conn.execute(
            "INSERT INTO permits(id,session_id,subject_id,material_id,family,track_key,version,"
            "body_hash,scope_json,status,issued_at,issued_seq) VALUES(?,?,?,?,?,?,?,?,?, 'active',?,?)",
            (permit_id, session_id, subj["id"], m["id"], m["family"], m["track_key"],
             m["version"], m["body_hash"], m["scope_json"], ts, seq))
        _evt(conn, "permit_issued", inst_id=subj["inst_id"], subject_id=subj["id"],
             session_id=session_id, permit_id=permit_id, material_id=m["id"],
             detail={"family": m["family"], "version": m["version"], "scope": _j(m, "scope_json"),
                     "body_hash": m["body_hash"], "device_id": att["device_id"],
                     "attest_nonce": att["nonce"]})
        body["result"] = "completed"
        body["permit_id"] = permit_id
        outcome = "completed"
        record_ref = permit_id
    _finalize_attestation(conn, att, target=session_id, outcome=outcome, record_ref=record_ref)
    conn.execute("COMMIT")
    body["session"] = get_session(conn, session_id, principal)
    if idem_key:
        begin_tx(conn); _idem_put(conn, idem_key, scope, 200, body); conn.execute("COMMIT")
    return 200, body


def revoke(conn, session_id, principal, idem_key=None, attestation=None):
    """参与人撤销（对进行中会话表达撤销意愿，或撤销已发许可）。必须绑定参与人设备证明。"""
    scope = f"revoke:{session_id}"
    if idem_key:
        hit = _idem_get(conn, idem_key, scope)
        if hit:
            code, body, _ = hit
            body["replayed"] = True
            return code, body
    begin_tx(conn)
    if attestation is None:
        conn.execute("ROLLBACK")
        raise EngineError("device_attestation_required",
                          "本入口的状态变更必须绑定本站有效设备证明", 401)
    att = verify_attestation(conn, attestation)
    if att["action"] != "revoke" or att["session_id"] != session_id:
        conn.execute("ROLLBACK")
        raise EngineError("request_fields_replaced", "设备证明与本次撤销不一致", 409)
    if att["replay"]:
        conn.execute("ROLLBACK")
        s = get_session(conn, session_id, principal)
        return 200, {"result": att["outcome"] or "already_revoked", "replayed": True,
                     "session": s, "session_id": session_id, "attest_nonce": att["nonce"]}

    r = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
    if not r:
        conn.execute("ROLLBACK")
        raise EngineError("session_not_found", "会话不存在", 404)
    if principal["role"] != "subject":
        conn.execute("ROLLBACK")
        raise EngineError("forbidden", "只有参与人本人可以撤销", 403)
    linked = conn.execute("SELECT id FROM subjects WHERE user_id=?",
                          (principal["id"],)).fetchone()
    if not linked or linked["id"] != r["subject_id"]:
        conn.execute("ROLLBACK")
        raise EngineError("session_not_found", "会话不存在", 404)
    subj = get_subject(conn, r["subject_id"])
    if att["inst_id"] != subj["inst_id"]:
        conn.execute("ROLLBACK")
        raise EngineError("site_mismatch", "设备不属于本机构，拒绝变更", 409)

    ts = now()
    inst_id = subj["inst_id"]
    if r["status"] == "open":
        conn.execute("UPDATE sessions SET status='withdrawn',withdrawn_at=? WHERE id=?",
                     (ts, session_id))
        _evt(conn, "session_withdrawn", inst_id=inst_id, subject_id=r["subject_id"],
             session_id=session_id, detail={"at": ts, "device_id": att["device_id"],
                                            "attest_nonce": att["nonce"]})
        _consume_and_finalize(conn, att, target=session_id, outcome="withdrawn", record_ref=ts)
        conn.execute("COMMIT")
        body = {"result": "withdrawn", "session_id": session_id, "at": ts,
                "attest_nonce": att["nonce"]}
    elif r["status"] == "completed":
        p = conn.execute("SELECT * FROM permits WHERE session_id=? AND status='active'",
                         (session_id,)).fetchone()
        if not p:
            # 已是终态：没有新的状态变更，不占用随机数、不留新凭据
            conn.execute("ROLLBACK")
            body = {"result": "already_revoked", "session_id": session_id}
            if idem_key:
                begin_tx(conn); _idem_put(conn, idem_key, scope, 200, body); conn.execute("COMMIT")
            return 200, body
        conn.execute("UPDATE permits SET status='revoked',revoked_at=? WHERE id=?",
                     (ts, p["id"]))
        _evt(conn, "permit_revoked", inst_id=inst_id, subject_id=r["subject_id"],
             session_id=session_id, permit_id=p["id"],
             detail={"at": ts, "version": p["version"], "device_id": att["device_id"],
                     "attest_nonce": att["nonce"]})
        _consume_and_finalize(conn, att, target=session_id, outcome="revoked",
                              record_ref=p["id"])
        conn.execute("COMMIT")
        body = {"result": "revoked", "permit_id": p["id"], "at": ts,
                "attest_nonce": att["nonce"]}
    elif r["status"] == "withdrawn":
        conn.execute("ROLLBACK")
        body = {"result": "already_withdrawn", "session_id": session_id}
    else:
        conn.execute("ROLLBACK")
        raise EngineError("session_blocked", "会话已因材料停用冻结，无需撤销", 409)
    s = get_session(conn, session_id, principal)
    body["session"] = s
    if idem_key:
        begin_tx(conn); _idem_put(conn, idem_key, scope, 200, body); conn.execute("COMMIT")
    return 200, body


# ---------------- 许可评估 / 执行确认 ----------------

def _permits_for(conn, subject_id):
    rows = conn.execute(
        "SELECT * FROM permits WHERE subject_id=? ORDER BY issued_seq DESC", (subject_id,)).fetchall()
    out = []
    for p in rows:
        d = dict(p)
        d["scope"] = _j(p, "scope_json")
        out.append(d)
    return out


def _open_requirements(conn, subject_id, family=None, track=None):
    """进行中会话尚缺的角色。"""
    rows = conn.execute(
        "SELECT * FROM sessions WHERE subject_id=? AND status='open'", (subject_id,)).fetchall()
    res = []
    for r in rows:
        m = conn.execute("SELECT * FROM materials WHERE id=?", (r["material_id"],)).fetchone()
        if family and m["family"] != family:
            continue
        if track and m["track_key"] != track:
            continue
        missing = [x["role"] for x in get_session(conn, r["id"])["slots"] if not x["filled"]]
        res.append({"session_id": r["id"], "family": m["family"], "version": m["version"],
                    "remaining_roles": missing})
    return res


def evaluate(conn, subject_id, op, purpose=None):
    """实际操作前查询：依据材料版本、获准范围、尚缺条件。"""
    subj = get_subject(conn, subject_id)
    if op not in KNOWN_OPS:
        raise EngineError("bad_op", f"未知操作 {op}")
    permits = _permits_for(conn, subject_id)
    covering = [p for p in permits if op in p["scope"]]
    # 以“最新的一份覆盖该操作的许可”为唯一裁定者：它若被撤销，不得回落到更旧许可复活权限
    newest = covering[0] if covering else None

    result = {"subject_id": subject_id, "op": op, "purpose": purpose,
              "allowed": False, "basis": None, "scope": None, "missing": None}

    if newest is None:
        result["reason"] = "no_permit"
        result["missing"] = {
            "open_sessions": _open_requirements(conn, subject_id),
            "hint": "尚无覆盖该操作的有效许可，需要完成全部必签角色",
        }
        return result
    if newest["status"] == "revoked":
        result["reason"] = "revoked"
        result["basis"] = {"permit_id": newest["id"], "family": newest["family"],
                           "version": newest["version"], "body_hash": newest["body_hash"],
                           "track_key": newest["track_key"], "issued_at": newest["issued_at"]}
        result["scope"] = newest["scope"]
        result["missing"] = {"hint": "最新许可已被参与人撤销；撤销后的新操作一律拒绝"}
        return result

    base = newest  # 最新有效许可
    result["basis"] = {
        "permit_id": base["id"], "family": base["family"], "version": base["version"],
        "body_hash": base["body_hash"], "track_key": base["track_key"],
        "issued_at": base["issued_at"],
    }
    result["scope"] = base["scope"]

    # 再次同意：同 track 的现行新版若把该操作列为需重新同意，未发生的相关操作立即冻结
    latest_mat = conn.execute(
        "SELECT * FROM materials WHERE track_key=? AND status='active' ORDER BY version DESC LIMIT 1",
        (base["track_key"],)).fetchone()
    if latest_mat and latest_mat["requires_reconsent"] \
            and op in _j(latest_mat, "reconsent_ops_json", []) \
            and latest_mat["version"] > base["version"]:
        result["reason"] = "frozen_reconsent"
        result["allowed"] = False
        result["missing"] = {
            "requires_reconsent_version": latest_mat["version"],
            "family": latest_mat["family"],
            "open_sessions": _open_requirements(conn, subject_id, latest_mat["family"],
                                                latest_mat["track_key"]),
            "hint": "规则修订要求对该操作再次同意，新版补签齐备后解锁",
        }
        return result

    result["allowed"] = True
    result["reason"] = "ok"
    return result


def execute(conn, subject_id, op, *, purpose=None, principal=None, idem_key=None,
            attestation=None):
    """操作实际发生前的执行确认（与撤销竞争时由写锁分出唯一先后）。必须绑定本站设备证明。"""
    scope = f"execute:{subject_id}:{op}:{purpose or ''}"
    if idem_key:
        hit = _idem_get(conn, idem_key, scope)
        if hit:
            code, body, _ = hit
            body["replayed"] = True
            return code, body
    begin_tx(conn)
    if attestation is None:
        conn.execute("ROLLBACK")
        raise EngineError("device_attestation_required",
                          "本入口的状态变更必须绑定本站有效设备证明", 401)
    att = verify_attestation(conn, attestation)
    if att["action"] != "execute":
        conn.execute("ROLLBACK")
        raise EngineError("request_fields_replaced", "设备证明与本次执行确认不一致", 409)
    if att["replay"]:
        conn.execute("ROLLBACK")
        # 同载荷重试复用首个回执（performed/denied 都返回第一次的结论）
        rid = att["record_ref"]
        prior = rid and conn.execute("SELECT * FROM executions WHERE id=?", (int(rid),)).fetchone()
        if prior:
            if prior["result"] == "denied":
                return 200, {"result": "denied", "execution_id": prior["id"],
                             "reason": prior["reason"], "replayed": True,
                             "attest_nonce": att["nonce"]}
            return 200, {"result": prior["result"], "execution_id": prior["id"],
                         "performed_at": prior["created_at"], "replayed": True,
                         "attest_nonce": att["nonce"]}
        return 200, {"result": "replayed", "replayed": True, "attest_nonce": att["nonce"]}

    subj = get_subject(conn, subject_id)
    if att["inst_id"] != subj["inst_id"]:
        conn.execute("ROLLBACK")
        raise EngineError("site_mismatch", "设备不属于本机构，拒绝变更", 409)
    if principal and principal["role"] == "site" and principal["inst_id"] != subj["inst_id"]:
        conn.execute("ROLLBACK")
        raise EngineError("cross_institution", "资源不属于本机构", 404)

    # 同一“新增用途”不允许重复登记；无用途的常规操作按次确认。
    # 命中既有记录时不产生新变更：不占用随机数、不留新凭据。
    if purpose:
        prior = conn.execute(
            "SELECT * FROM executions WHERE subject_id=? AND op=? AND purpose=? AND result='performed'",
            (subject_id, op, purpose)).fetchone()
        if prior:
            conn.execute("ROLLBACK")
            return 200, {"result": "already_performed", "execution_id": prior["id"],
                         "performed_at": prior["created_at"],
                         "basis_version": prior["version"]}

    ev = evaluate(conn, subject_id, op, purpose)
    ts = now()
    # 确认要落一条执行记录（无论放行 performed 还是拒绝 denied，都是一次权威状态变更），
    # 此刻原子占用随机数并写凭据，与执行记录同一事务提交/回滚。
    consume_attestation(conn, att)
    if ev["allowed"]:
        cur = conn.execute(
            "INSERT INTO executions(subject_id,op,purpose,permit_id,material_family,version,"
            "result,created_at) VALUES(?,?,?,?,?,?,'performed',?)",
            (subject_id, op, purpose, ev["basis"]["permit_id"], ev["basis"]["family"],
             ev["basis"]["version"], ts))
        _evt(conn, "op_performed", inst_id=subj["inst_id"], subject_id=subject_id,
             permit_id=ev["basis"]["permit_id"],
             detail={"op": op, "purpose": purpose, "family": ev["basis"]["family"],
                     "version": ev["basis"]["version"], "execution_id": cur.lastrowid,
                     "device_id": att["device_id"], "attest_nonce": att["nonce"]})
        _finalize_attestation(conn, att, target=subject_id, outcome="performed",
                              record_ref=str(cur.lastrowid))
        conn.execute("COMMIT")
        body = {"result": "performed", "execution_id": cur.lastrowid, "performed_at": ts,
                "basis": ev["basis"], "scope": ev["scope"], "attest_nonce": att["nonce"]}
    else:
        cur = conn.execute(
            "INSERT INTO executions(subject_id,op,purpose,permit_id,material_family,version,"
            "result,reason,created_at) VALUES(?,?,?,?,?,?,'denied',?,?)",
            (subject_id, op, purpose,
             ev["basis"]["permit_id"] if ev["basis"] else None,
             ev["basis"]["family"] if ev["basis"] else None,
             ev["basis"]["version"] if ev["basis"] else None,
             ev["reason"], ts))
        _evt(conn, "op_denied", inst_id=subj["inst_id"], subject_id=subject_id,
             permit_id=ev["basis"]["permit_id"] if ev["basis"] else None,
             detail={"op": op, "purpose": purpose, "reason": ev["reason"],
                     "missing": ev["missing"], "execution_id": cur.lastrowid,
                     "device_id": att["device_id"], "attest_nonce": att["nonce"]})
        _finalize_attestation(conn, att, target=subject_id, outcome="denied",
                              record_ref=str(cur.lastrowid))
        conn.execute("COMMIT")
        body = {"result": "denied", "execution_id": cur.lastrowid, "reason": ev["reason"],
                "basis": ev["basis"], "scope": ev["scope"], "missing": ev["missing"],
                "attest_nonce": att["nonce"]}
    if idem_key:
        begin_tx(conn); _idem_put(conn, idem_key, scope, 200, body); conn.execute("COMMIT")
    return 200, body


def list_executions(conn, subject_id):
    return [dict(r) for r in conn.execute(
        "SELECT * FROM executions WHERE subject_id=? ORDER BY id", (subject_id,))]


def list_permits(conn, subject_id):
    return _permits_for(conn, subject_id)


# ---------------- 审计 ----------------

def audit_events(conn, principal, *, inst_id=None, limit=100):
    """审计可见性：现场仅本机构；规则维护员可见全局但参与人身份打码；参与人仅本人。"""
    sql = "SELECT * FROM events WHERE 1=1"
    args = []
    if principal["role"] == "site":
        sql += " AND inst_id=?"; args.append(principal["inst_id"])
    elif principal["role"] == "subject":
        linked = conn.execute("SELECT id FROM subjects WHERE user_id=?",
                              (principal["id"],)).fetchone()
        sql += " AND subject_id=?"; args.append(linked["id"] if linked else "!")
    elif inst_id:
        sql += " AND inst_id=?"; args.append(inst_id)
    sql += " ORDER BY seq DESC LIMIT ?"; args.append(limit)
    rows = conn.execute(sql, args).fetchall()
    mask = principal["role"] == "admin"
    out = []
    for r in rows:
        d = dict(r)
        d["detail"] = json.loads(d.pop("detail_json"))
        if mask and d.get("subject_id"):
            d["subject_id"] = "SUBJ-MASKED"
            if "signer_name" in d["detail"]:
                d["detail"]["signer_name"] = "***"
        out.append(d)
    return out
