"""领域引擎：材料封存发布、签署会话、许可评估、再次同意、撤销/执行竞争。

所有写操作都在单个 BEGIN IMMEDIATE 事务内完成“读状态→判定→落盘→写事件流水”，
因此撤销与执行、双终端重复落款等竞争只按持久化先后收敛为一个结果。
"""
import json
import secrets
import hashlib

from db import get_conn, begin_tx, now, seal_body, track_key

KNOWN_OPS = ["blood_draw", "imaging", "medication", "sample_reuse"]
KNOWN_ROLES = ["subject", "witness", "site_owner"]
ROLE_LABELS = {"subject": "参与人", "witness": "见证者", "site_owner": "现场负责人"}


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
         idem_key=None):
    scope = f"sign:{session_id}:{role}"
    if idem_key:
        hit = _idem_get(conn, idem_key, scope)
        if hit:
            code, body, _ = hit
            body["replayed"] = True
            return code, body

    begin_tx(conn)
    r = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
    if not r:
        conn.execute("ROLLBACK")
        raise EngineError("session_not_found", "会话不存在", 404)
    subj = get_subject(conn, r["subject_id"])
    m = conn.execute("SELECT * FROM materials WHERE id=?", (r["material_id"],)).fetchone()

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

    # 会话状态（与撤销、停用竞争时以本事务内读到的持久化状态为准）
    if r["status"] == "blocked" or m["status"] == "retired":
        if r["status"] == "open":
            ts = now()
            conn.execute("UPDATE sessions SET status='blocked',blocked_at=? WHERE id=?",
                         (ts, session_id))
            _evt(conn, "session_blocked", inst_id=subj["inst_id"], subject_id=subj["id"],
                 session_id=session_id, material_id=m["id"],
                 detail={"reason": "material_retired", "version": m["version"]})
            conn.execute("COMMIT")
        else:
            conn.execute("ROLLBACK")
        raise EngineError("material_retired", "材料在签署途中被停用，本会话已冻结", 409)
    if r["status"] == "withdrawn":
        conn.execute("ROLLBACK")
        raise EngineError("session_withdrawn", "参与人已撤销，不能再落款", 409)
    if r["status"] == "completed":
        conn.execute("ROLLBACK")
        raise EngineError("already_completed", "所有必需角色已完成签署", 409)

    # 重复落款：槽位已被占用时，同一落款人=重复提交取首次结果；不同落款人=目标冲突，
    # 槽位归属以先提交者为准，系统给出唯一可说明状态
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

    ts = now()
    cur = conn.execute(
        "INSERT INTO signatures(session_id,slot_id,role,signer_principal,signer_name,"
        "body_hash,sig_hash,created_at) VALUES(?,?,?,?,?,?,?,?)",
        (session_id, slot["id"], role, signer_principal, signer_name,
         m["body_hash"], sig_hash, ts))
    if role == "witness":
        conn.execute("UPDATE sign_slots SET token_used=1,signer_name=? WHERE id=?",
                     (signer_name, slot["id"]))
    else:
        conn.execute("UPDATE sign_slots SET signer_name=? WHERE id=?", (signer_name, slot["id"]))
    _evt(conn, "signed", inst_id=subj["inst_id"], subject_id=subj["id"],
         session_id=session_id, material_id=m["id"],
         detail={"role": role, "signer_name": signer_name, "body_hash": m["body_hash"],
                 "version": m["version"]})

    body = {"result": "signed", "role": role, "signed_at": ts}
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
                     "body_hash": m["body_hash"]})
        body["result"] = "completed"
        body["permit_id"] = permit_id
    conn.execute("COMMIT")
    body["session"] = get_session(conn, session_id, principal)
    if idem_key:
        begin_tx(conn); _idem_put(conn, idem_key, scope, 200, body); conn.execute("COMMIT")
    return 200, body


def revoke(conn, session_id, principal, idem_key=None):
    """参与人撤销（对进行中会话表达撤销意愿，或撤销已发许可）。"""
    scope = f"revoke:{session_id}"
    if idem_key:
        hit = _idem_get(conn, idem_key, scope)
        if hit:
            code, body, _ = hit
            body["replayed"] = True
            return code, body
    begin_tx(conn)
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

    ts = now()
    inst_id = conn.execute("SELECT inst_id FROM subjects WHERE id=?",
                           (r["subject_id"],)).fetchone()["inst_id"]
    if r["status"] == "open":
        conn.execute("UPDATE sessions SET status='withdrawn',withdrawn_at=? WHERE id=?",
                     (ts, session_id))
        _evt(conn, "session_withdrawn", inst_id=inst_id, subject_id=r["subject_id"],
             session_id=session_id, detail={"at": ts})
        conn.execute("COMMIT")
        body = {"result": "withdrawn", "session_id": session_id, "at": ts}
    elif r["status"] == "completed":
        p = conn.execute("SELECT * FROM permits WHERE session_id=? AND status='active'",
                         (session_id,)).fetchone()
        if not p:
            conn.execute("ROLLBACK")
            body = {"result": "already_revoked", "session_id": session_id}
            if idem_key:
                begin_tx(conn); _idem_put(conn, idem_key, scope, 200, body); conn.execute("COMMIT")
            return 200, body
        conn.execute("UPDATE permits SET status='revoked',revoked_at=? WHERE id=?",
                     (ts, p["id"]))
        _evt(conn, "permit_revoked", inst_id=inst_id, subject_id=r["subject_id"],
             session_id=session_id, permit_id=p["id"],
             detail={"at": ts, "version": p["version"]})
        conn.execute("COMMIT")
        body = {"result": "revoked", "permit_id": p["id"], "at": ts}
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


def execute(conn, subject_id, op, *, purpose=None, principal=None, idem_key=None):
    """操作实际发生前的执行确认（与撤销竞争时由写锁分出唯一先后）。"""
    scope = f"execute:{subject_id}:{op}:{purpose or ''}"
    if idem_key:
        hit = _idem_get(conn, idem_key, scope)
        if hit:
            code, body, _ = hit
            body["replayed"] = True
            return code, body
    begin_tx(conn)
    subj = get_subject(conn, subject_id)
    if principal and principal["role"] == "site" and principal["inst_id"] != subj["inst_id"]:
        conn.execute("ROLLBACK")
        raise EngineError("cross_institution", "资源不属于本机构", 404)

    # 同一“新增用途”不允许重复登记；无用途的常规操作按次确认
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
    if ev["allowed"]:
        cur = conn.execute(
            "INSERT INTO executions(subject_id,op,purpose,permit_id,material_family,version,"
            "result,created_at) VALUES(?,?,?,?,?,?,'performed',?)",
            (subject_id, op, purpose, ev["basis"]["permit_id"], ev["basis"]["family"],
             ev["basis"]["version"], ts))
        _evt(conn, "op_performed", inst_id=subj["inst_id"], subject_id=subject_id,
             permit_id=ev["basis"]["permit_id"],
             detail={"op": op, "purpose": purpose, "family": ev["basis"]["family"],
                     "version": ev["basis"]["version"], "execution_id": cur.lastrowid})
        conn.execute("COMMIT")
        body = {"result": "performed", "execution_id": cur.lastrowid, "performed_at": ts,
                "basis": ev["basis"], "scope": ev["scope"]}
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
                     "missing": ev["missing"], "execution_id": cur.lastrowid})
        conn.execute("COMMIT")
        body = {"result": "denied", "execution_id": cur.lastrowid, "reason": ev["reason"],
                "basis": ev["basis"], "scope": ev["scope"], "missing": ev["missing"]}
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
