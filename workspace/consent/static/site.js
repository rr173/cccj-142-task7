boot("site", "app", async main => {
  const user = getUser();
  const INST = user.inst_id;
  let current = null; // 当前选中的本机构对象

  // ---------- 设备可信登记 ----------
  function deviceBannerHtml() {
    const info = DeviceAuth.certInfo(INST, "site");
    if (info) {
      return `<div class="card okbox" id="devBanner">
        本机已完成可信登记：设备证书 ${esc(info.cert_id)}（第 ${info.gen} 代）·
        可落款角色 ${esc((info.roles||[]).join("/"))}。所有落款/执行确认都将由本机私钥签署。
        <button class="small ghost" id="devInspect">自检状态</button>
      </div>`;
    }
    return `<div class="card" id="devBanner">
      <h2>本站设备可信登记（首次使用必填）</h2>
      <p class="muted">在本机生成终端签名密钥（私钥不出设备），粘贴本机构安全管理员/现场负责人签发的
        一次性注册码完成登记。未登记设备不能新增签名槽记录或执行确认。</p>
      <div class="row">
        <div style="flex:2"><label>一次性注册码</label><input id="devCode" placeholder="粘贴注册码"></div>
        <div><label>设备标识</label><input id="devLabel" value="现场终端"></div>
        <div style="flex:0 0 auto"><label>&nbsp;</label><button id="devRegister">登记本机</button></div>
      </div>
      <div id="devMsg"></div>
    </div>`;
  }

  async function renderBanner() {
    const old = document.getElementById("devBanner");
    const wrap = document.createElement("div");
    wrap.innerHTML = deviceBannerHtml();
    const fresh = wrap.firstElementChild;
    if (old) old.replaceWith(fresh); else main.prepend(fresh);
    bindBanner(fresh);
  }
  function bindBanner(el) {
    const reg = el.querySelector("#devRegister");
    if (reg) reg.onclick = async () => {
      const box = el.querySelector("#devMsg");
      const code = el.querySelector("#devCode").value.trim();
      const label = el.querySelector("#devLabel").value.trim() || "现场终端";
      if (!code) { toast(box, new Error("请粘贴一次性注册码")); return; }
      try {
        await DeviceAuth.register(INST, "site", code, label);
        await renderBanner();
      } catch (e) { toast(box, e); }
    };
    const insp = el.querySelector("#devInspect");
    if (insp) insp.onclick = async () => {
      try {
        const st = await DeviceAuth.inspect(INST, "site");
        alert(`设备 ${st.device_id}\n证书 ${st.cert_id}（第 ${st.gen} 代）\n状态：${st.status}` +
              `${st.quarantined ? "\n⚠ 该设备已被隔离" : ""}\n有效期内：${st.within_validity}`);
      } catch (e) { alert(e.message); }
    };
  }

  main.innerHTML = `
  <div id="bannerSlot"></div>
  <div class="card">
    <h2>本站设备可信管理</h2>
    <p class="muted">签发一次性设备注册码（明文仅此一次显示）；查看本站设备与证书代次、即时隔离、
      颁发轮换授权；每条状态变更都可在设备审计中核对凭据。</p>
    <div class="row">
      <div><label>注册码可用角色</label>
        <select id="rcRole">
          <option value="site">现场设备(site)</option>
          <option value="subject">主体设备(subject)</option>
          <option value="witness">见证设备(witness)</option>
        </select></div>
      <div><label>有效期(分钟)</label><input id="rcMin" type="number" value="60"></div>
      <div style="flex:0 0 auto"><label>&nbsp;</label><button id="rcIssue">签发注册码</button></div>
    </div>
    <div id="rcMsg"></div>
    <div id="devAdmin"></div>
  </div>
  <div class="card">
    <h2>本机构办理对象</h2>
    <table><thead><tr><th>选择</th><th>对象</th><th>首选语种</th><th>人群条件</th></tr></thead>
      <tbody id="subjRows"></tbody></table>
  </div>

  <div id="workArea"></div>`;
  await renderBanner();
  await renderDeviceAdmin();

  async function renderDeviceAdmin() {
    const wrap = document.getElementById("devAdmin");
    let devices = [];
    try { devices = await api("GET", "/api/devices"); } catch (e) { return; }
    wrap.innerHTML = `
      <details style="margin-top:8px"><summary>本站设备（${devices.length}）与注册码</summary>
        <div id="rcList"></div>
        <table style="margin-top:8px"><thead><tr><th>设备</th><th>标识</th><th>证书代次/状态</th>
          <th>隔离</th><th>操作</th></tr></thead><tbody>
        ${devices.map(d => `<tr>
          <td class="hash">${esc(d.device_id)}</td><td>${esc(d.device_label)}</td>
          <td>${d.certificates.map(c => `${esc(c.cert_id)} v${c.gen} <span class="muted">[${esc(c.status)}]</span>`).join("<br>")}</td>
          <td>${d.quarantined ? `<span class="pill no">${esc(d.quarantined_reason||"")}</span>` : '<span class="pill ok">正常</span>'}</td>
          <td>
            ${d.quarantined ? "" : `<button class="small danger" data-q="${esc(d.device_id)}">隔离</button>`}
            <button class="small ghost" data-rot="${esc(d.current_cert_id)}">轮换授权</button>
          </td></tr>`).join("")}
        </tbody></table>
      </details>`;
    wrap.querySelectorAll("[data-q]").forEach(b => b.onclick = async () => {
      const reason = prompt("隔离原因（必填）");
      if (!reason) return;
      try { await api("POST", "/api/devices/quarantine", { device_id: b.dataset.q, reason });
        await renderDeviceAdmin();
      } catch (e) { alert(e.message); }
    });
    wrap.querySelectorAll("[data-rot]").forEach(b => b.onclick = async () => {
      try { const r = await api("POST", "/api/devices/rotate/prepare", { cert_id: b.dataset.rot });
        prompt("一次性轮换授权码（10 分钟内由该设备双签完成轮换）：", r.rotation_nonce);
      } catch (e) { alert(e.message); }
    });
    try {
      const codes = await api("GET", "/api/devices/register-codes");
      document.getElementById("rcList").innerHTML =
        `<table><thead><tr><th>编号</th><th>角色</th><th>状态</th><th>到期</th></tr></thead><tbody>` +
        codes.map(c => `<tr><td class="hash">${esc(c.code_ref)}</td><td>${esc(c.roles.join(","))}</td>
          <td>${esc(c.status)}</td><td class="muted">${esc(c.expires_at)}</td></tr>`).join("") +
        "</tbody></table>";
    } catch { /* ignore */ }
  }
  document.getElementById("rcIssue").onclick = async () => {
    const box = document.getElementById("rcMsg");
    try {
      const r = await api("POST", "/api/devices/register-codes", {
        roles: [document.getElementById("rcRole").value],
        minutes: Number(document.getElementById("rcMin").value || 60),
      });
      box.innerHTML = `<div class="okbox">一次性注册码（仅显示一次，请当面/带外交付）：
        <div class="hash" style="font-size:15px">${esc(r.code)}</div>
        编号 ${esc(r.code_ref)} · 角色 ${esc(r.roles.join(","))} · ${r.minutes} 分钟有效</div>`;
      await renderDeviceAdmin();
    } catch (e) { toast(box, e); }
  };

  const subjects = await api("GET", "/api/subjects");
  document.getElementById("subjRows").innerHTML = subjects.map(s => `
    <tr><td><button class="small" data-pick="${s.id}">办理</button></td>
      <td>${esc(s.name)} <span class="muted">${esc(s.id)}</span></td>
      <td>${esc(s.language)}</td>
      <td><code>${esc(JSON.stringify(s.conditions))}</code></td></tr>`).join("");
  document.querySelectorAll("[data-pick]").forEach(b => b.onclick = () => loadSubject(b.dataset.pick));

  async function loadSubject(sid) {
    current = await api("GET", `/api/subjects/${sid}`);
    const area = document.getElementById("workArea");
    area.innerHTML = `
    <div class="card">
      <h2>可开单材料 — ${esc(current.name)}（只显示 机构/首选语种/人群条件 全部吻合的现行版）</h2>
      <div id="eligMsg"></div>
      <table><thead><tr><th>材料族</th><th>版本</th><th>正文</th><th>必签角色</th>
        <th>允许操作</th><th>封存指纹</th><th></th></tr></thead><tbody id="eligRows"></tbody></table>
    </div>
    <div class="card">
      <h2>办理进度与具体缺项</h2>
      <div id="sessList"></div>
    </div>
    <div class="card">
      <h2>操作前许可查询 / 执行确认（采血·影像·用药·留存再利用）</h2>
      <div class="row">
        <div><label>操作</label><select id="opSel">
          ${Object.entries(OP_LABELS).map(([k, v]) => `<option value="${k}">${v}</option>`).join("")}
        </select></div>
        <div><label>用途（sample_reuse 的新增用途必填）</label><input id="purpose" placeholder="如 biomarker-study-2026"></div>
        <div style="flex:0 0 auto"><label>&nbsp;</label><button id="btnCheck">查询许可</button>
        <button id="btnExec" class="ghost">执行确认</button></div>
      </div>
      <div id="checkMsg"></div>
    </div>
    <div class="card">
      <h2>执行/拒绝记录（撤销前已形成的记录保留）</h2>
      <table><thead><tr><th>#</th><th>时刻(UTC)</th><th>操作</th><th>用途</th><th>结果</th>
        <th>依据版本</th><th>原因</th></tr></thead><tbody id="execRows"></tbody></table>
    </div>`;
    await refreshAll();
    document.getElementById("btnCheck").onclick = () => check(false);
    document.getElementById("btnExec").onclick = () => check(true);
  }

  async function refreshAll() {
    const [elig, sessions, execs] = await Promise.all([
      api("GET", `/api/subjects/${current.id}/eligibility`),
      api("GET", `/api/subjects/${current.id}/sessions`),
      api("GET", `/api/subjects/${current.id}/executions`),
    ]);
    document.getElementById("eligRows").innerHTML = elig.map(m => `
      <tr>
        <td>${esc(m.family)}</td><td>v${m.version}</td>
        <td><details><summary>${esc(m.body.slice(0, 24))}…</summary><pre>${esc(m.body)}</pre></details></td>
        <td>${roleList(m.roles)}</td><td>${opList(m.scope)}</td>
        <td class="hash">${esc(m.body_hash.slice(0, 16))}…</td>
        <td>${m.eligible
          ? `<button class="small" data-start="${m.id}">开单</button>`
          : `<span class="pill no">${esc(m.reject_reasons.join(","))}</span>`}</td>
      </tr>`).join("");
    document.querySelectorAll("[data-start]").forEach(b => b.onclick = async () => {
      try {
        await api("POST", `/api/subjects/${current.id}/sessions`, { material_id: Number(b.dataset.start) });
        await refreshAll();
      } catch (e) { alert(e.message); }
    });

    document.getElementById("sessList").innerHTML = sessions.length ? sessions.map(s => `
      <div style="border-bottom:1px solid #edf0f3;padding:10px 0">
        <b>${esc(s.material.family)} v${s.material.version}</b> ${pill(s.status)}
        <span class="muted">会话 ${esc(s.id)} · 开单 ${esc(s.created_at)} · 指纹 ${esc(s.material.body_hash.slice(0, 12))}…</span>
        <table style="margin-top:6px"><tr>
          ${s.slots.map(sl => `<td style="border:0">${esc(sl.role_label)}：${
            sl.filled ? `<span class="pill ok">${esc(sl.signer_name)} @ ${esc(sl.signed_at)}</span>`
                      : `<span class="pill no miss">缺</span>`}</td>`).join("")}
        </tr></table>
        ${s.status === "open"
          ? `<div style="margin-top:6px">
             <button class="small ghost" data-sign="${s.id}">我（现场负责人）签署</button>
             <button class="small ghost" data-tokens="${s.id}">生成见证者签名链接</button>
             <span class="muted">参与人请用本人账号在自助页签署</span></div>
             <div id="tk-${s.id}"></div>`
          : s.status === "completed"
            ? `<div class="muted" style="margin-top:4px">许可已生成；许可操作以该封存版本为依据。</div>`
            : `<div class="muted" style="margin-top:4px">${
                s.status === "blocked" ? "材料停用导致冻结，须用新版重新开单，不会降级到旧版。" : "参与人已撤销。"}</div>`}
      </div>`).join("") : `<p class="muted">暂无会话。</p>`;

    document.querySelectorAll("[data-sign]").forEach(b => b.onclick = async () => {
      try {
        const sid = b.dataset.sign;
        const sess = sessions.find(x => x.id === sid);
        const attestation = await DeviceAuth.attest("sign", {
          instId: INST, certRole: "site", role: "site_owner",
          sessionId: sid, bodyDigest: sess.material.body_hash,
        });
        await api("POST", `/api/sessions/${sid}/sign`, { role: "site_owner", attestation });
        await refreshAll();
      } catch (e) {
        alert(e.message + (e.code ? ` [${e.code}]` : ""));
        if (["cert_rotated", "cert_invalid", "device_quarantined", "device_not_registered"]
            .includes(e.code)) await renderBanner();
      }
    });
    document.querySelectorAll("[data-tokens]").forEach(b => b.onclick = async () => {
      try {
        const r = await api("POST", `/api/sessions/${b.dataset.tokens}/tokens`, {});
        const links = Object.entries(r.tokens).map(([role, tk]) =>
          `<div>${ROLE_LABELS[role]} 一次性签名链接：
            <a href="/witness.html?session=${r.session_id}&role=${role}&token=${tk}" target="_blank">
            /witness.html?session=${r.session_id}&role=${role}&token=…</a>
            <div class="hash">${tk}</div></div>`).join("");
        document.getElementById("tk-" + b.dataset.tokens).innerHTML =
          `<div class="okbox">${links || "暂无待签角色"}</div>`;
      } catch (e) { alert(e.message); }
    });

    document.getElementById("execRows").innerHTML = execs.map(e => `
      <tr><td>${e.id}</td><td class="muted">${esc(e.created_at)}</td>
        <td>${esc(OP_LABELS[e.op] || e.op)}</td><td>${esc(e.purpose || "")}</td>
        <td>${e.result === "performed"
          ? '<span class="pill ok">已执行</span>' : '<span class="pill no">已拒绝</span>'}</td>
        <td>${e.material_family ? esc(e.material_family) + " v" + e.version : "—"}</td>
        <td>${esc(e.reason || "")}</td></tr>`).join("");
  }

  async function check(doExecute) {
    const box = document.getElementById("checkMsg");
    const op = document.getElementById("opSel").value;
    const purpose = document.getElementById("purpose").value || null;
    try {
      if (doExecute) {
        const bodyDigest = await CT.digestHex(
          { subject_id: current.id, op, purpose: purpose ?? null });
        const attestation = await DeviceAuth.attest("execute", {
          instId: INST, certRole: "site", role: "site",
          sessionId: null, bodyDigest,
        });
        const r = await api("POST", `/api/subjects/${current.id}/execute`,
          { op, purpose, attestation });
        box.innerHTML = r.result === "performed"
          ? `<div class="okbox">✅ 已执行确认（#${r.execution_id}），依据 ${esc(r.basis.family)} v${r.basis.version}
             <div class="hash">${esc(r.basis.body_hash.slice(0, 20))}…</div>获准范围：${opList(r.scope)}</div>`
          : `<div class="err">⛔ 执行被拒绝：<b>${esc(r.reason)}</b><pre>${esc(JSON.stringify(r.missing, null, 2))}</pre></div>`;
      } else {
        const r = await api("GET", `/api/subjects/${current.id}/check?op=${op}`
          + (purpose ? `&purpose=${encodeURIComponent(purpose)}` : ""));
        if (r.allowed) {
          box.innerHTML = `<div class="okbox">允许：依据 ${esc(r.basis.family)} v${r.basis.version}
            （${esc(r.basis.issued_at)}）<br>获准范围：${opList(r.scope)}</div>`;
        } else {
          box.innerHTML = `<div class="err">不允许（${esc(r.reason)}）
            <pre>${esc(JSON.stringify(r.missing, null, 2))}</pre></div>`;
        }
      }
      await refreshAll();
    } catch (e) { toast(box, e); }
  }
});
