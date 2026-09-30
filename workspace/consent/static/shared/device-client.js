/*
 * 设备可信证明 —— 浏览器客户端助手（依赖 shared/ed25519.js 的 CT）。
 *
 * 职责：
 *  - 本机生成并持久化 Ed25519 终端密钥（localStorage，私钥不出浏览器）；
 *  - 凭一次性注册码完成设备登记，保存服务端签发的终端证书；
 *  - 为 sign/revoke/execute 三类动作领取挑战、用本机私钥签署完整请求，
 *    组装可直接提交的 attestation 字段；
 *  - 同载荷重试复用同一挑战随机数（服务端据 request_fp 判定同载荷并回首个回执）。
 *
 * 与 app.js 解耦：本文件只暴露 window.DeviceAuth，页面在写操作前先 await DeviceAuth.attest(...)。
 */
(function () {
  "use strict";
  const KEY_PREFIX = "consent_device_v1:";

  async function apiRaw(method, path, body) {
    const headers = { "Content-Type": "application/json" };
    const tok = localStorage.getItem("consent_token");
    if (tok) headers.Authorization = "Bearer " + tok;
    const resp = await fetch(path, { method, headers,
      body: body ? JSON.stringify(body) : undefined });
    let data = null;
    try { data = await resp.json(); } catch { /* ignore */ }
    if (!resp.ok) {
      const e = new Error(data?.message || ("HTTP " + resp.status));
      e.code = data?.error; e.body = data; e.status = resp.status;
      throw e;
    }
    return data;
  }

  // 登录设备按 (机构, 角色) 存一把密钥；见证设备无登录态，机构由注册码/证书携带，按 'witness' 全局存。
  function storeKey(instId, role) { return KEY_PREFIX + (instId ?? "ANY") + ":" + role; }
  function storeCert(instId, role) { return KEY_PREFIX + "cert:" + (instId ?? "ANY") + ":" + role; }

  async function loadOrCreateKey(instId, role) {
    const k = localStorage.getItem(storeKey(instId, role));
    if (k) return JSON.parse(k);
    const key = await CT.generateKey();
    const rec = { publicHex: key.publicHex, secretHex: key.secretHex };
    localStorage.setItem(storeKey(instId, role), JSON.stringify(rec));
    return rec;
  }
  function loadCert(instId, role) {
    const raw = localStorage.getItem(storeCert(instId, role));
    return raw ? JSON.parse(raw) : null;
  }
  function saveCert(instId, role, cert) {
    localStorage.setItem(storeCert(instId, role), JSON.stringify(cert));
  }

  /**
   * 用一次性注册码登记本设备。code 由现场管理员在本站签发。
   * role: 'subject' | 'site' | 'witness'
   */
  async function register(instId, role, code, deviceLabel) {
    const key = await loadOrCreateKey(instId, role);
    // CSR 钉住机构/设备标识/公钥，由新私钥签名以证明持有对应私钥；
    // 一次性注册码本身作为登记凭证在传输层提交（明文仅本次使用，库存哈希）。
    const csr = {
      alg: "CT-REGISTER-CSR/v1",
      code_ref: "",
      device_label: deviceLabel, public_hex: key.publicHex, inst_id: instId,
    };
    const csrSig = await CT.sign(key.secretHex, CT.canonicalBytes(csr));
    const resp = await apiRaw("POST", "/api/devices/register", {
      code, device_label: deviceLabel, public_hex: key.publicHex, csr_sig: csrSig,
    });
    saveCert(instId, role, resp.cert);
    return resp;
  }

  /** 设备自检：返回代次/隔离状态/有效期。 */
  async function inspect(instId, role) {
    const cert = loadCert(instId, role);
    if (!cert) return null;
    const key = JSON.parse(localStorage.getItem(storeKey(instId, role)));
    const nonce = String(Date.now()) + Math.random().toString(36).slice(2);
    const proof = { alg: "CT-INSPECT/v1", cert_id: cert.payload.cert_id, nonce };
    const proofSig = await CT.sign(key.secretHex, CT.canonicalBytes(proof));
    return await apiRaw("POST", "/api/devices/inspect", { cert, nonce, proof_sig: proofSig });
  }

  /**
   * 组装一次状态变更的设备证明。
   * action: 'sign' | 'revoke' | 'execute'
   * ctx: { instId, role, sessionId?, bodyDigest, actionRole }
   *   - sign 的 role 是落款角色（subject/witness/site_owner），证书角色按机构设备选取；
   *   - execute 的 role 固定 'site'，sessionId 传 null。
   * 返回 attestation 对象，放入写请求 body.attestation。
   *
   * @param reuse 传入上一次的 attestation 可复用其挑战（同载荷重试）。
   */
  async function attest(action, ctx, reuse) {
    const { instId, certRole, role, sessionId, bodyDigest } = ctx;
    const cert = loadCert(instId, certRole);
    if (!cert) {
      const e = new Error("本设备尚未完成可信登记，请先输入一次性注册码");
      e.code = "device_not_registered"; throw e;
    }
    const key = JSON.parse(localStorage.getItem(storeKey(instId, certRole)));

    let chResp, challenge, challengeSig;
    if (reuse && reuse.challenge && reuse.cert === cert) {
      challenge = reuse.challenge; challengeSig = reuse.challenge_sig;
    } else {
      chResp = await apiRaw("POST", "/api/devices/challenge", {
        cert, action, role, session_id: sessionId ?? null,
        inst_id: instId, body_digest: bodyDigest,
      });
      challenge = chResp.challenge; challengeSig = chResp.signature;
    }

    const sreq = {
      alg: "CT-SIGN-REQUEST/v1",
      cert_id: challenge.cert_id, nonce: challenge.nonce, action: challenge.action,
      session_id: challenge.session_id, role: challenge.role,
      body_digest: challenge.body_digest, inst_id: challenge.inst_id,
      challenge_sig: challengeSig,
    };
    const terminalSig = await CT.sign(key.secretHex, CT.canonicalBytes(sreq));
    return {
      cert, challenge, challenge_sig: challengeSig, terminal_sig: terminalSig,
      cert_id: challenge.cert_id, nonce: challenge.nonce, action: challenge.action,
      session_id: challenge.session_id, role: challenge.role,
      body_digest: challenge.body_digest, inst_id: challenge.inst_id,
    };
  }

  function hasCert(instId, certRole) {
    return !!loadCert(instId, certRole);
  }
  function certInfo(instId, certRole) {
    const c = loadCert(instId, certRole);
    return c ? { cert_id: c.payload.cert_id, gen: c.payload.gen,
      device_id: c.payload.device_id, roles: c.payload.roles,
      not_after_ms: c.payload.not_after_ms } : null;
  }
  function clear(instId, certRole) {
    localStorage.removeItem(storeCert(instId, certRole));
    localStorage.removeItem(storeKey(instId, certRole));
  }

  window.DeviceAuth = {
    register, inspect, attest, hasCert, certInfo, clear,
    // 供页面在收到 cert_rotated/cert_invalid 后引导轮换；轮换流程单独入口
    async rotate(instId, certRole, rotationNonce) {
      const old = JSON.parse(localStorage.getItem(storeKey(instId, certRole)));
      const newKey = await CT.generateKey();
      const oldCert = loadCert(instId, certRole);
      const csr = {
        alg: "CT-ROTATION-CSR/v1", rotation_nonce: rotationNonce,
        old_cert_id: oldCert.payload.cert_id, device_id: oldCert.payload.device_id,
        new_public_hex: newKey.publicHex,
      };
      const newSig = await CT.sign(newKey.secretHex, CT.canonicalBytes(csr));
      const oldSig = await CT.sign(old.secretHex, CT.canonicalBytes(csr));
      const resp = await apiRaw("POST", "/api/devices/rotate", {
        rotation_nonce: rotationNonce, new_public_hex: newKey.publicHex,
        new_sig: newSig, old_sig: oldSig,
      });
      localStorage.setItem(storeKey(instId, certRole),
        JSON.stringify({ publicHex: newKey.publicHex, secretHex: newKey.secretHex }));
      saveCert(instId, certRole, resp.cert);
      return resp;
    },
  };
})();
