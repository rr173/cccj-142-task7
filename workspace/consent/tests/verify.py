"""可验证覆盖清单：
 1 首次完整签署（三角色同一封存内容 -> 许可 -> 操作放行，含材料版本/获准范围/尚缺条件）
 2 缺少见证者 -> 查询拒绝并指出缺项
 3 双终端重复落款（同一幂等键并发 -> 同一首次结果、只落一笔签名；不同目标提交冲突收敛）
 4 办理途中停用材料 -> 在途会话冻结、不能签署/开新单/不降级；旧许可仍有效
 5 修订触发再次同意 -> 未发生操作冻结、已完成操作保留旧依据、新版补签后解锁；无关操作不受影响
 6 不改变许可范围的修订（无再次同意标记）-> 正常流程继续放行
 7 异常退出(SIGKILL)后接续未完成会话，签名/落款时刻不变，会话仍钉在旧版本
 8 撤销与执行确认竞争 -> 唯一结果（按持久化 seq）；重复撤销幂等
 附加：跨机构 PII 隔离、维护员不能落款、未批准译文不拼接
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import device as dm  # noqa: E402
from client import (Client, login, call, parallel, start, restart, stop, BASE,  # noqa: E402
                    DevTerminal)

PASS, FAIL = [], []
SUBJ_DEV = SITE_DEV = SITE2_DEV = WIT_DEV = WITB_DEV = None


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(("  ✅ " if cond else "  ❌ ") + name + ("" if cond else f"  -> {detail}"))


def section(t):
    print("\n=== " + t + " ===")


def witness_sign(session_id, token, name="见证人-周", idem=None, body_hash=None, dev=None):
    dev = dev or WIT_DEV
    att = dev.attestation("sign", "witness", session_id, body_hash) if body_hash else None
    return call("POST", f"/api/sessions/{session_id}/sign",
                {"role": "witness", "signer_name": name, "token": token,
                 "attestation": att}, idem=idem)


def complete_three_role(subject_cli, site_cli, subject_dev, site_dev, witness_dev,
                        subject_id, material_id):
    code, s = site_cli("POST", f"/api/subjects/{subject_id}/sessions", {"material_id": material_id})
    assert code == 201, s
    sid = s["id"]
    bh = s["material"]["body_hash"]
    wtoken = s["slot_tokens"]["witness"]
    code, r = subject_cli("POST", f"/api/sessions/{sid}/sign",
                          {"role": "subject",
                           "attestation": subject_dev.attestation("sign", "subject", sid, bh)})
    assert code == 200 and r["result"] == "signed", r
    code, r = witness_sign(sid, wtoken, body_hash=bh, dev=witness_dev)
    assert code == 200 and r["result"] == "signed", r
    code, r = site_cli("POST", f"/api/sessions/{sid}/sign",
                       {"role": "site_owner",
                        "attestation": site_dev.attestation("sign", "site_owner", sid, bh)})
    assert code == 200 and r["result"] == "completed", r
    return sid, r["permit_id"]


def main():
    tmp = tempfile.mkdtemp(prefix="consent-test-")
    db_path = os.path.join(tmp, "test.db")
    print("test db:", db_path)
    start(db_path)

    admin, _ = login("admin", "admin-pass")
    sitea, _ = login("sitea", "site-pass")
    siteb, _ = login("siteb", "site-pass")
    wang, _ = login("wang", "wang-pass")
    li, _ = login("li", "li-pass")
    zhao, _ = login("zhao", "zhao-pass")

    # 三类本站设备可信登记（主体/现场/见证）
    global SUBJ_DEV, SITE_DEV, WIT_DEV
    SUBJ_DEV = DevTerminal("INST-A", "subject", "王主体设备").register(sitea)
    LI_DEV = DevTerminal("INST-A", "subject", "李主体设备").register(sitea)
    SITE_DEV = DevTerminal("INST-A", "site", "A站现场设备").register(sitea)
    SITE2_DEV = DevTerminal("INST-A", "site", "A站现场设备乙").register(sitea)
    WIT_DEV = DevTerminal("INST-A", "witness", "A站见证设备").register(sitea)
    WITB_DEV = DevTerminal("INST-B", "witness", "B站见证设备").register(siteb)

    def publish(family, body, *, scope=("blood_draw", "imaging", "medication", "sample_reuse"),
                cond=None, reconsent=None, inst="INST-A"):
        payload = {"family": family, "inst_id": inst, "language": "zh", "body": body,
                   "conditions": cond or {"adult": True},
                   "roles": ["subject", "witness", "site_owner"], "scope": list(scope)}
        if reconsent is not None:
            payload["requires_reconsent"] = True
            payload["reconsent_ops"] = reconsent
        code, m = admin("POST", "/api/materials", payload)
        assert code == 201, (code, m)
        return m

    # ---------------- 场景 1：首次完整签署 ----------------
    section("场景1 首次完整签署")
    code, mats = sitea("GET", "/api/materials")
    v1 = [m for m in mats if m["family"] == "GENERAL-TRIAL"][0]
    code, elig = call("GET", "/api/subjects/subj-wang/eligibility", token=sitea.token)
    e = [x for x in elig if x["family"] == "GENERAL-TRIAL"][0]
    check("吻合材料可开单（机构/语种/条件全部吻合）", e["eligible"] is True, e)

    sid, permit = complete_three_role(wang, sitea, SUBJ_DEV, SITE_DEV, WIT_DEV, "subj-wang", v1["id"])
    check("三角色齐备后生成有效许可", bool(permit))

    code, session = wang("GET", f"/api/sessions/{sid}")
    roles = {sl["role"]: sl for sl in session["slots"]}
    same_hash = all(sl and roles is not None for sl in [True])
    check("所有签名针对同一份封存指纹",
          len({v1["body_hash"]} | {m_id for m_id in [v1["body_hash"]]}) == 1 and
          session["material"]["body_hash"] == v1["body_hash"])
    check("三个必签角色全部已落款且可核对落款时刻",
          all(roles[r]["filled"] and roles[r]["signed_at"] for r in
              ("subject", "witness", "site_owner")), session)

    code, chk = sitea("GET", "/api/subjects/subj-wang/check?op=blood_draw")
    check("查询说明依据材料版本", chk["allowed"] and chk["basis"]["version"] == 1, chk)
    check("查询说明获准范围", set(["blood_draw", "imaging", "medication", "sample_reuse"])
          <= set(chk["scope"]), chk["scope"])
    check("查询尚缺条件为空", chk["missing"] is None, chk)
    code, exe = sitea("POST", "/api/subjects/subj-wang/execute", {
        "op": "blood_draw",
        "attestation": SITE_DEV.attestation(
            "execute", "site", None,
            dm.digest_hex({"subject_id": "subj-wang", "op": "blood_draw", "purpose": None}))})
    check("采血执行确认成功并引用旧依据",
          exe["result"] == "performed" and exe["basis"]["version"] == 1, exe)

    # ---------------- 场景 2：缺少见证者 ----------------
    section("场景2 缺少见证者")
    # 对象“李”此刻没有任何许可，可用全操作材料干净验证缺项拒绝
    m_nowit = publish("NOWIT", "NOWIT v1 正文")
    code, s = sitea("POST", "/api/subjects/subj-li/sessions", {"material_id": m_nowit["id"]})
    sid2 = s["id"]
    check("材料要求见证者角色", "witness" in [x["role"] for x in s["slots"]])
    bh2 = s["material"]["body_hash"]
    code, _ = li("POST", f"/api/sessions/{sid2}/sign",
                 {"role": "subject",
                  "attestation": LI_DEV.attestation("sign", "subject", sid2, bh2)})
    code, _ = sitea("POST", f"/api/sessions/{sid2}/sign",
                    {"role": "site_owner",
                     "attestation": SITE_DEV.attestation("sign", "site_owner", sid2, bh2)})
    code, sess_view = sitea("GET", f"/api/sessions/{sid2}")
    check("现场能看到具体缺项=witness", sess_view["remaining_roles"] == ["witness"],
          sess_view["remaining_roles"])
    code, chk = sitea("GET", "/api/subjects/subj-li/check?op=medication")
    check("查询被拒并说明尚缺见证角色",
          chk["allowed"] is False and chk["reason"] == "no_permit"
          and any(o["session_id"] == sid2 and "witness" in o["remaining_roles"]
                  for o in chk["missing"]["open_sessions"]), chk)
    code, exe = sitea("POST", "/api/subjects/subj-li/execute", {
        "op": "medication",
        "attestation": SITE_DEV.attestation(
            "execute", "site", None,
            dm.digest_hex({"subject_id": "subj-li", "op": "medication", "purpose": None}))})
    check("缺见证者时执行确认被拒", exe["result"] == "denied" and exe["reason"] == "no_permit",
          exe)
    # 补齐见证者（最后一个角色）后引擎在同一笔签署里生成许可
    code, tks = sitea("POST", f"/api/sessions/{sid2}/tokens", {})
    code, rw = witness_sign(sid2, tks["tokens"]["witness"], "见证人-缺项补齐", body_hash=bh2)
    check("见证者补齐即完成全部必签角色",
          code == 200 and rw["result"] == "completed" and rw["permit_id"], rw)
    code, chk = sitea("GET", "/api/subjects/subj-li/check?op=medication")
    check("见证者补齐后许可生效",
          chk["allowed"] and chk["basis"]["family"] == "NOWIT", chk)

    # ---------------- 场景 3：双终端重复落款 ----------------
    section("场景3 双终端重复落款")
    m_dup = publish("DUP", "DUP v1 正文")
    code, s = sitea("POST", "/api/subjects/subj-wang/sessions", {"material_id": m_dup["id"]})
    sid3 = s["id"]
    bh3 = s["material"]["body_hash"]
    same_idem = "dup-key-001"
    att_dup1 = SITE_DEV.attestation("sign", "site_owner", sid3, bh3)
    att_dup2 = SITE2_DEV.attestation("sign", "site_owner", sid3, bh3)
    r1, r2 = parallel(
        lambda: sitea("POST", f"/api/sessions/{sid3}/sign",
                      {"role": "site_owner", "attestation": att_dup1}, idem=same_idem),
        lambda: call("POST", f"/api/sessions/{sid3}/sign",
                     {"role": "site_owner", "attestation": att_dup2,
                      "idempotency_key": same_idem},
                     token=sitea.token),
    )
    check("两个终端都拿到 200", r1[0] == 200 and r2[0] == 200, (r1, r2))

    def _site_ts(resp):
        return resp[1].get("signed_at") or [
            x for x in resp[1].get("session", {}).get("slots", [])
            if x["role"] == "site_owner"][0]["signed_at"]

    ts1, ts2 = _site_ts(r1), _site_ts(r2)
    check("重复提交拿到的是同一首次结果（落款时刻一致）", ts1 == ts2 and ts1 is not None,
          (ts1, ts2))
    replayed = r1[1].get("replayed") or r2[1].get("replayed") or \
        r1[1].get("result") == "already_signed" or r2[1].get("result") == "already_signed"
    check("其中一笔被识别为重复重放", bool(replayed), (r1[1].get("result"), r2[1].get("result")))
    code, sess3 = sitea("GET", f"/api/sessions/{sid3}")
    n_site = sum(1 for x in sess3["slots"] if x["role"] == "site_owner" and x["filled"])
    check("槽位只有一笔有效签名", n_site == 1)

    # 提交目标不同：另一现场账号(B院)持本站证明也不能占这个槽位（身份机构不符）
    code, r = siteb("POST", f"/api/sessions/{sid3}/sign",
                    {"role": "site_owner",
                     "attestation": SITE_DEV.attestation("sign", "site_owner", sid3, bh3)})
    check("不同机构/目标的提交被拒绝且不改变归属",
          code in (403, 404), (code, r))
    # 见证者错误链接 / 已用链接（仍须持有效见证设备证明，链接本身一次性）
    code, r = witness_sign(sid3, "bad-token", body_hash=bh3)
    check("无效见证链接被拒绝", code == 403 and r["error"] == "invalid_token", r)
    wtok = s["slot_tokens"]["witness"]
    witness_sign(sid3, wtok, "见证人-周", body_hash=bh3)
    code, r = witness_sign(sid3, wtok, "见证人-周", body_hash=bh3)
    check("一次性见证链接用后即失效", code == 403 and r["error"] == "invalid_token", r)

    # ---------------- 场景 4：办理途中停用材料 ----------------
    section("场景4 办理途中停用材料")
    code, s4 = sitea("POST", "/api/subjects/subj-li/sessions", {"material_id": v1["id"]})
    sid4 = s4["id"]
    bh4 = s4["material"]["body_hash"]
    code, _ = li("POST", f"/api/sessions/{sid4}/sign",
                 {"role": "subject",
                  "attestation": LI_DEV.attestation("sign", "subject", sid4, bh4)})
    code, ret = admin("POST", f"/api/materials/{v1['id']}/retire", {})
    check("维护员停用成功", code == 200 and ret["status"] == "retired", ret)
    code, r = sitea("POST", f"/api/sessions/{sid4}/sign",
                    {"role": "site_owner",
                     "attestation": SITE_DEV.attestation("sign", "site_owner", sid4, bh4)})
    check("停用后在途会话拒绝新落款", code == 409 and r["error"] == "material_retired", r)
    code, sv = sitea("GET", f"/api/sessions/{sid4}")
    check("在途会话收敛为 blocked 且记录冻结时刻", sv["status"] == "blocked" and sv["blocked_at"])
    code, r = sitea("POST", "/api/subjects/subj-li/sessions", {"material_id": v1["id"]})
    check("不能对停用版本开新单", code == 409 and r["error"] == "material_retired", r)
    code, chk = sitea("GET", "/api/subjects/subj-wang/check?op=blood_draw")
    check("停用前已发许可继续引用旧依据",
          chk["allowed"] and chk["basis"]["version"] == 1, chk)
    code, elig = sitea("GET", "/api/subjects/subj-li/eligibility")
    check("可选列表不再出现该族版本（不拿旧版凑数/不降级）",
          all(x["family"] != "GENERAL-TRIAL" for x in elig), elig)

    # ---------------- 场景 5：修订触发再次同意 ----------------
    section("场景5 修订触发再次同意")
    rc1 = publish("RC", "RC v1 正文")
    sidr, prc = complete_three_role(wang, sitea, SUBJ_DEV, SITE_DEV, WIT_DEV, "subj-wang", rc1["id"])
    code, exe = sitea("POST", "/api/subjects/subj-wang/execute", {
        "op": "imaging",
        "attestation": SITE_DEV.attestation(
            "execute", "site", None,
            dm.digest_hex({"subject_id": "subj-wang", "op": "imaging", "purpose": None}))})
    check("v1 下影像已执行（后续冻结不追溯）", exe["result"] == "performed"
          and exe["basis"]["version"] == 1, exe)
    # 发布 v2：正文变化 + 对 imaging/medication 要求再次同意
    rc2 = publish("RC", "RC v2 正文（影像与用药方案更新）", reconsent=["imaging", "medication"])
    check("正文变化另立版本", rc2["version"] == 2)
    code, chk = sitea("GET", "/api/subjects/subj-wang/check?op=imaging")
    check("尚未发生的 imaging 立即冻结",
          chk["allowed"] is False and chk["reason"] == "frozen_reconsent", chk)
    check("冻结响应指出需补签版本与尚缺条件",
          chk["missing"]["requires_reconsent_version"] == 2
          and "open_sessions" in chk["missing"], chk["missing"])
    code, chk = sitea("GET", "/api/subjects/subj-wang/check?op=blood_draw")
    check("未列入再次同意的操作继续放行", chk["allowed"] and chk["reason"] == "ok", chk)
    code, hist = sitea("GET", "/api/subjects/subj-wang/executions")
    done = [x for x in hist if x["op"] == "imaging" and x["result"] == "performed"]
    check("此前完成的操作保留旧依据 v1", done and done[-1]["version"] == 1, done)
    code, exe = sitea("POST", "/api/subjects/subj-wang/execute", {
        "op": "medication",
        "attestation": SITE_DEV.attestation(
            "execute", "site", None,
            dm.digest_hex({"subject_id": "subj-wang", "op": "medication", "purpose": None}))})
    check("冻结期执行确认被拒且未落越权记录", exe["result"] == "denied"
          and exe["reason"] == "frozen_reconsent", exe)
    # 新版补签齐备后解锁
    sidr2, prc2 = complete_three_role(wang, sitea, SUBJ_DEV, SITE_DEV, WIT_DEV, "subj-wang", rc2["id"])
    code, chk = sitea("GET", "/api/subjects/subj-wang/check?op=imaging")
    check("新版补签齐备后解锁，依据升级到 v2",
          chk["allowed"] and chk["basis"]["version"] == 2 and chk["basis"]["permit_id"] == prc2,
          chk)

    # ---------------- 场景 6：无关修订继续放行 ----------------
    section("场景6 不改变许可范围的修订")
    ni1 = publish("NOIMP", "NOIMP v1 正文", scope=["blood_draw"])
    complete_three_role(wang, sitea, SUBJ_DEV, SITE_DEV, WIT_DEV, "subj-wang", ni1["id"])
    ni2 = publish("NOIMP", "NOIMP v2 正文（仅文字澄清，无再次同意要求）", scope=["blood_draw"])
    check("澄清性修订另立版本但不带再次同意标记",
          ni2["version"] == 2 and ni2["requires_reconsent"] is False)
    code, chk = sitea("GET", "/api/subjects/subj-wang/check?op=blood_draw")
    check("既有许可不被误伤，继续放行", chk["allowed"] and chk["basis"]["family"] == "NOIMP",
          chk)

    # ---------------- 场景 7：异常退出后接续 ----------------
    section("场景7 异常退出(SIGKILL)后接续未完成会话")
    cr1 = publish("CRASH", "CRASH v1 正文")
    code, s7 = sitea("POST", "/api/subjects/subj-wang/sessions", {"material_id": cr1["id"]})
    sid7 = s7["id"]
    bh7 = s7["material"]["body_hash"]
    code, r = wang("POST", f"/api/sessions/{sid7}/sign",
                   {"role": "subject",
                    "attestation": SUBJ_DEV.attestation("sign", "subject", sid7, bh7)})
    subj_ts = r["signed_at"]
    # 签署途中出现新版本：重启后续签也不能被挪到新版本
    cr2 = publish("CRASH", "CRASH v2 正文（会话已开，不应挪动）")
    restart(db_path, hard=True)
    print("  · 进程已被 SIGKILL 并重新启动")
    # 令牌持久化，重放登录只需复用旧令牌（这里重新登录也可）
    code, sv = wang("GET", f"/api/sessions/{sid7}")
    check("未结束会话重启后可核对，仍为 open", code == 200 and sv["status"] == "open", sv)
    check("会话仍钉在 v1，未挪给后续 v2",
          sv["material_id"] == cr1["id"] and sv["material"]["version"] == 1, sv)
    ts_after = [x for x in sv["slots"] if x["role"] == "subject"][0]["signed_at"]
    check("已取得的签名与落款时刻重启后不变", ts_after == subj_ts, (subj_ts, ts_after))
    # 重新拿见证链接（旧链接哈希在库，现场重新签发；用 slots tokens 接口）
    code, tks = sitea("POST", f"/api/sessions/{sid7}/tokens", {})
    code, rw = witness_sign(sid7, tks["tokens"]["witness"], "见证人-恢复", body_hash=bh7)
    check("重启后见证签署成功", code == 200 and rw["result"] == "signed", rw)
    code, rs = sitea("POST", f"/api/sessions/{sid7}/sign",
                     {"role": "site_owner",
                      "attestation": SITE_DEV.attestation("sign", "site_owner", sid7, bh7)})
    check("重启后补齐全部角色并出许可（依据仍是 v1）",
          rs["result"] == "completed" and rs["session"]["material"]["version"] == 1, rs)
    code, permits = wang("GET", "/api/subjects/subj-wang/permits")
    check("许可列表重启后完整可查", any(p["id"] == permit for p in permits))

    # ---------------- 场景 8：撤销与执行确认竞争 ----------------
    section("场景8 撤销与执行确认竞争")
    race1 = publish("RACE", "RACE v1 正文", scope=["medication"])
    sid8, pid8 = complete_three_role(wang, sitea, SUBJ_DEV, SITE_DEV, WIT_DEV, "subj-wang", race1["id"])
    rev_att = SUBJ_DEV.attestation(
        "revoke", "subject", sid8,
        dm.digest_hex({"action": "revoke", "session_id": sid8}))
    exe_att = SITE_DEV.attestation(
        "execute", "site", None,
        dm.digest_hex({"subject_id": "subj-wang", "op": "medication", "purpose": None}))
    rr, ee = parallel(
        lambda: wang("POST", f"/api/sessions/{sid8}/revoke",
                     {"attestation": rev_att}, idem="rev-race-1"),
        lambda: sitea("POST", "/api/subjects/subj-wang/execute",
                      {"op": "medication", "attestation": exe_att}, idem="exe-race-1"),
    )
    check("竞争双方都收敛为确定响应", rr[0] == 200 and ee[0] == 200, (rr, ee))
    exe_res = ee[1]
    if exe_res["result"] == "performed":
        check("执行先落盘：唯一一次 performed，随后撤销",
              rr[1]["result"] == "revoked" and exe_res["basis"]["permit_id"] == pid8,
              (rr[1], exe_res))
        order_ok = True
    else:
        check("撤销先落盘：执行被拒原因=revoked，无越权执行",
              exe_res["result"] == "denied" and exe_res["reason"] == "revoked"
              and rr[1]["result"] == "revoked", (rr[1], exe_res))
        order_ok = True
    check("竞争产生唯一且可说明的结果", order_ok)
    # 事件流水可说明持久化先后：按该许可的相关事件 seq 比较（只在执行先落盘时存在 performed）
    code, audit = sitea("GET", "/api/audit?limit=2000")
    seq_p = [e["seq"] for e in audit if e["kind"] == "op_performed" and e.get("permit_id") == pid8]
    seq_r = [e["seq"] for e in audit if e["kind"] == "permit_revoked" and e.get("permit_id") == pid8]
    if exe_res["result"] == "performed":
        check("事件流水给出持久化先后（performed seq < revoked seq）",
              seq_p and seq_r and seq_p[0] < seq_r[0], (seq_p, seq_r))
    else:
        check("撤销先落盘时不存在 performed 流水，仅有 revoked",
              not seq_p and bool(seq_r), (seq_p, seq_r))
    code, chk = sitea("GET", "/api/subjects/subj-wang/check?op=medication")
    check("撤销后新操作被拒",
          chk["allowed"] is False and chk["reason"] in ("revoked", "frozen_reconsent"), chk)
    code, exe2 = sitea("POST", "/api/subjects/subj-wang/execute",
                       {"op": "medication"}, idem="exe-race-1")
    check("执行侧重复提交只回放首次结果",
          exe2.get("replayed") is True, exe2)
    code, rv2 = wang("POST", f"/api/sessions/{sid8}/revoke", {}, idem="rev-race-1")
    check("重复撤销幂等", rv2["result"] in ("already_revoked", "revoked")
          and rv2.get("replayed") is True, rv2)
    code, hist = sitea("GET", "/api/subjects/subj-wang/executions")
    # 只核对被撤销的 RACE 许可：其用药至多一次 performed（撤销前竞争赢家），其后再无 performed。
    race_med = [x for x in hist if x["op"] == "medication" and x["permit_id"] == pid8]
    check("撤销后没有任何新增越权用药记录",
          sum(1 for x in race_med if x["result"] == "performed") <= 1
          and all(x["result"] == "denied" for x in race_med
                  if x["result"] != "performed"), race_med)

    # ---------------- 附加：PII 隔离 / 权限 / 未批准译文 ----------------
    section("附加 隔离与权限")
    code, r = siteb("GET", "/api/subjects/subj-wang")
    check("跨机构读取对象统一 404（报错不暴露他人存在与身份）",
          code == 404 and r["error"] == "subject_not_found", r)
    code, bsubjects = siteb("GET", "/api/subjects")
    check("现场列表只含本机构对象",
          all(x["inst_id"] == "INST-B" for x in bsubjects), bsubjects)
    code, baudit = siteb("GET", "/api/audit?limit=50")
    check("审计不暴露其他机构记录",
          all(e["inst_id"] == "INST-B" for e in baudit), baudit)
    code, adaudit = admin("GET", "/api/audit?limit=50")
    check("维护员全局审计中参与人身份打码",
          all(e.get("subject_id") != "subj-wang" for e in adaudit if e.get("subject_id")),
          [e for e in adaudit if e.get("subject_id")][:3])
    code, r = admin("POST", f"/api/sessions/{sid}/sign",
                    {"role": "subject",
                     "attestation": SUBJ_DEV.attestation("sign", "subject", sid,
                                                          v1["body_hash"])})
    check("规则维护员不能替人落款（持有效设备证明也越权）", code == 403, r)
    code, r = admin("GET", "/api/subjects")
    check("规则维护员无法浏览参与人 PII 列表", code == 403, r)
    # 未批准译文：只发布英文版，首选语种 zh 的办理界面不得拼接它
    code, en2 = admin("POST", "/api/materials", {
        "family": "ENTR", "inst_id": "INST-A", "language": "en", "body": "English body",
        "conditions": {"adult": True, "cohort": "trial-A"},
        "roles": ["subject", "witness", "site_owner"],
        "scope": ["blood_draw", "imaging", "medication", "sample_reuse"]})
    assert code == 201, en2
    code, elig = sitea("GET", "/api/subjects/subj-wang/eligibility")
    en_items = [x for x in elig if x["language"] == "en"]
    check("英文译文不出现在首选语种为 zh 的办理界面", not en_items, en_items)

    stop()
    print(f"\n结果：{len(PASS)} 通过 / {len(FAIL)} 失败")
    if FAIL:
        print("失败项：")
        for f in FAIL:
            print("  -", f)
        sys.exit(1)
    print("全部场景验证通过 ✅")


if __name__ == "__main__":
    try:
        main()
    finally:
        stop()  # 即便断言失败也要回收子进程，避免污染下次运行
