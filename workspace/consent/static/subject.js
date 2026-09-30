boot("subject", "app", async main => {
  const user = getUser();
  const INST = user.inst_id;
  let me;
  async function loadMe() {
    const r = await api("GET", "/api/me");
    me = r.subject;
  }
  await loadMe();

  // ---------- 主体设备可信登记 ----------
  function bannerHtml() {
    const info = DeviceAuth.certInfo(INST, "subject");
    if (info) {
      return `<div class="card okbox" id="devBanner">本机主体设备已可信登记：证书 ${esc(info.cert_id)}
        （第 ${info.gen} 代）。你的每次签署/撤销均由本机私钥落款。
        <button class="small ghost" id="devInspect">自检</button></div>`;
    }
    return `<div class="card" id="devBanner">
      <h2>主体设备可信登记（首次签署前必填）</h2>
      <p class="muted">本机生成终端密钥（私钥不出设备），粘贴现场负责人提供的一次性主体注册码完成登记。
        未登记的浏览器不能新增签署/撤销。</p>
      <div class="row">
        <div style="flex:2"><label>一次性注册码</label><input id="devCode"></div>
        <div><label>设备标识</label><input id="devLabel" value="本人设备"></div>
        <div style="flex:0 0 auto"><label>&nbsp;</label><button id="devRegister">登记本机</button></div>
      </div><div id="devMsg"></div></div>`;
  }
  async function renderBanner() {
    const old = document.getElementById("devBanner");
    const wrap = document.createElement("div");
    wrap.innerHTML = bannerHtml();
    const fresh = wrap.firstElementChild;
    if (old) old.replaceWith(fresh); else main.prepend(fresh);
    bind(fresh);
  }
  function bind(el) {
    const reg = el.querySelector("#devRegister");
    if (reg) reg.onclick = async () => {
      const box = el.querySelector("#devMsg");
      const code = el.querySelector("#devCode").value.trim();
      const label = el.querySelector("#devLabel").value.trim() || "本人设备";
      if (!code) { toast(box, new Error("请粘贴注册码")); return; }
      try { await DeviceAuth.register(INST, "subject", code, label); await renderBanner(); }
      catch (e) { toast(box, e); }
    };
    const insp = el.querySelector("#devInspect");
    if (insp) insp.onclick = async () => {
      try { const st = await DeviceAuth.inspect(INST, "subject");
        alert(`设备 ${st.device_id}\n证书 ${st.cert_id}（第 ${st.gen} 代）\n状态 ${st.status}` +
              (st.quarantined ? "\n⚠ 已被隔离" : ""));
      } catch (e) { alert(e.message); }
    };
  }

  main.innerHTML = `
  <div id="bannerSlot"></div>
  <div class="card">
    <h2>我的许可与办理中事项 — ${esc(me.name)}</h2>
    <p class="muted">你签过的每份材料都展示其<b>封存原文、版本与指纹</b>；会话自开单起即钉死在该版本，不会被挪到新版本。</p>
    <div id="sessList"></div>
  </div>

  <div class="card">
    <h2>当前许可（撤销后拒绝其后的新操作和新增用途；撤销前已形成的记录保留）</h2>
    <table><thead><tr><th>许可</th><th>材料</th><th>版本</th><th>获准范围</th><th>状态</th>
        <th>签发时刻(UTC)</th><th>封存指纹</th></tr></thead><tbody id="permitRows"></tbody></table>
  </div>

  <div class="card">
    <h2>与我相关的操作记录</h2>
    <table><thead><tr><th>#</th><th>时刻(UTC)</th><th>操作</th><th>用途</th><th>结果</th><th>依据版本</th></tr></thead>
      <tbody id="execRows"></tbody></table>
  </div>`;

  await renderBanner();
  async function refresh() {
    const [sessions, permits, execs] = await Promise.all([
      api("GET", `/api/subjects/${me.id}/sessions`),
      api("GET", `/api/subjects/${me.id}/permits`),
      api("GET", `/api/subjects/${me.id}/executions`),
    ]);
    document.getElementById("sessList").innerHTML = sessions.map(s => `
      <div style="border-bottom:1px solid #edf0f3;padding:10px 0">
        <b>${esc(s.material.family)} v${s.material.version}</b> ${pill(s.status)}
        <span class="muted">${esc(s.id)} · 开单 ${esc(s.created_at)}</span>
        <details><summary class="muted">查看封存原文与指纹</summary>
          <pre>${esc(s.material.body)}</pre>
          <div class="hash">封存指纹（正文/语种/条件/角色/范围）：${esc(s.material.body_hash)}</div>
        </details>
        <table style="margin-top:6px"><tr>
          ${s.slots.map(sl => `<td style="border:0">${esc(sl.role_label)}：${
            sl.filled ? `<span class="pill ok">${esc(sl.signer_name)} @ ${esc(sl.signed_at)}</span>`
                      : `<span class="pill no miss">缺</span>`}</td>`).join("")}
        </tr></table>
        ${s.status === "open"
          ? `<div style="margin-top:6px">
               <button class="small" data-sign="${s.id}">我（参与人）在线签署</button>
               <button class="small danger" data-revoke="${s.id}">撤销办理意愿</button>
             </div><div id="msg-${s.id}"></div>`
          : s.status === "completed"
            ? `<div style="margin-top:6px"><button class="small danger" data-revoke="${s.id}">撤销该许可</button>
               <span class="muted">撤销前已执行的记录仍合法保留，之后的新操作将被拒绝。</span>
               <div id="msg-${s.id}"></div></div>`
            : `<div class="muted" style="margin-top:4px">${
                s.status === "withdrawn" ? `已撤销于 ${esc(s.withdrawn_at)}`
                : `因材料停用冻结于 ${esc(s.blocked_at)}，请用新版重新办理`}</div>`}
      </div>`).join("") || `<p class="muted">暂无办理记录。</p>`;

    document.querySelectorAll("[data-sign]").forEach(b => b.onclick = async () => {
      const sid = b.dataset.sign;
      const box = document.getElementById("msg-" + sid);
      try {
        const sess = sessions.find(x => x.id === sid);
        const attestation = await DeviceAuth.attest("sign", {
          instId: INST, certRole: "subject", role: "subject",
          sessionId: sid, bodyDigest: sess.material.body_hash,
        });
        const r = await api("POST", `/api/sessions/${sid}/sign`, { role: "subject", attestation });
        okbox(box, (r.replayed ? "（重复提交，返回首次结果）" : "") +
          (r.result === "completed" ? `已签署且全部角色齐备，许可 ${r.permit_id} 已生成。`
          : "已记录你的签署。"));
        await refresh();
      } catch (e) {
        toast(box, e);
        if (["cert_rotated", "cert_invalid", "device_quarantined", "device_not_registered"]
            .includes(e.code)) await renderBanner();
      }
    });
    document.querySelectorAll("[data-revoke]").forEach(b => b.onclick = async () => {
      if (!confirm("确认撤销？撤销前已执行的记录保留，之后的新操作/新增用途会被拒绝。")) return;
      const sid = b.dataset.revoke;
      const box = document.getElementById("msg-" + sid);
      try {
        const sess = sessions.find(x => x.id === sid);
        const digest = await CT.digestHex(
          { action: "revoke", session_id: sid, body_hash: sess.material.body_hash });
        const attestation = await DeviceAuth.attest("revoke", {
          instId: INST, certRole: "subject", role: "subject",
          sessionId: sid, bodyDigest: digest,
        });
        const r = await api("POST", `/api/sessions/${sid}/revoke`, { attestation });
        okbox(box, "结果：" + r.result + (r.replayed ? "（重复提交，返回首次结果）" : ""));
        await refresh();
      } catch (e) {
        toast(box, e);
        if (["cert_rotated", "cert_invalid", "device_quarantined", "device_not_registered"]
            .includes(e.code)) await renderBanner();
      }
    });

    document.getElementById("permitRows").innerHTML = permits.map(p => `
      <tr><td>${esc(p.id)}</td><td>${esc(p.family)}</td><td>v${p.version}</td>
        <td>${opList(p.scope)}</td><td>${pill(p.status)}</td>
        <td>${esc(p.issued_at)}</td><td class="hash">${esc(p.body_hash.slice(0, 16))}…</td></tr>`)
      .join("") || `<tr><td colspan="7" class="muted">暂无许可</td></tr>`;

    document.getElementById("execRows").innerHTML = execs.map(e => `
      <tr><td>${e.id}</td><td class="muted">${esc(e.created_at)}</td>
        <td>${esc(OP_LABELS[e.op] || e.op)}</td><td>${esc(e.purpose || "")}</td>
        <td>${e.result === "performed" ? '<span class="pill ok">已执行</span>'
          : '<span class="pill no">已拒绝</span>'}</td>
        <td>${e.material_family ? esc(e.material_family) + " v" + e.version : "—"}</td></tr>`).join("");
  }
  await refresh();
});
