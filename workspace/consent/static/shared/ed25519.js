/*
 * 纯 JavaScript（BigInt）Ed25519 + 规范 JSON，零依赖，可在浏览器与 Node 运行。
 * 与服务端 ../device.py（RFC 8032）字节一致：同样的扩展坐标加法、clamp、SHA-512 规约。
 *
 * 浏览器环境用 crypto.subtle.digest('SHA-512')；Node 用 node:crypto。
 *
 * 对外暴露：
 *   CT.canonicalBytes(obj) / CT.digestHex(obj)
 *   CT.generateKey()      -> { publicHex, exportSecret(), sign(canonicalBytes) }
 *   CT.sign(secretHex, bytes) -> base64url
 *   CT.verify(publicHex, bytes, sigB64url) -> boolean
 *   CT.b64e(bytes)
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    const nodeCrypto = require("node:crypto");
    module.exports = factory(nodeCrypto);
  } else {
    root.CT = factory(null);
  }
})(typeof self !== "undefined" ? self : this, function (nodeCrypto) {
  "use strict";

  // ---------- 基础工具 ----------
  function utf8(s) { return new TextEncoder().encode(s); }

  async function sha512(bytes) {
    if (nodeCrypto) {
      return nodeCrypto.createHash("sha512").update(Buffer.from(bytes)).digest();
    }
    const ab = await crypto.subtle.digest("SHA-512", bytes);
    return new Uint8Array(ab);
  }
  // 同步 SHA-512：浏览器 subtle 仅异步，因此密钥操作整体是 async；Node 下可同步。
  const isNode = !!nodeCrypto;

  function b64e(u8) {
    let bin = "";
    for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function b64d(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  // ---------- 规范 JSON（与 device.py canonical_bytes 字节一致） ----------
  function canonicalBytes(value) {
    return utf8(canonical(value));
  }
  function canonical(v) {
    if (v === null) return "null";
    const t = typeof v;
    if (t === "boolean") return v ? "true" : "false";
    if (t === "number") {
      if (!Number.isFinite(v) || !Number.isSafeInteger(v)) {
        throw new TypeError("仅支持安全整数");
      }
      return String(v);
    }
    if (t === "string") return JSON.stringify(v);
    if (Array.isArray(v)) {
      return "[" + v.map((x) => {
        if (x === undefined) throw new TypeError("数组内不允许 undefined");
        return canonical(x);
      }).join(",") + "]";
    }
    if (t === "object") {
      const keys = Object.keys(v).filter((k) => v[k] !== undefined).sort();
      return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
    }
    throw new TypeError("不支持的类型: " + t);
  }
  function digestHexSync(bytes) {
    // Node 同步；浏览器请用 digestHex（async）
    const h = nodeCrypto.createHash("sha256").update(Buffer.from(bytes)).digest("hex");
    return h;
  }
  async function sha256Bytes(bytes) {
    if (nodeCrypto) return nodeCrypto.createHash("sha256").update(Buffer.from(bytes)).digest();
    return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  }
  async function digestHex(obj) {
    const h = await sha256Bytes(canonicalBytes(obj));
    return [...h].map((x) => x.toString(16).padStart(2, "0")).join("");
  }

  // ---------- Ed25519（与 device.py 对应） ----------
  const P = 2n ** 255n - 19n;
  const D = mod(-121665n * modPow(121666n, P - 2n, P), P);
  const L = 2n ** 252n + 27742317777372353535851937790883648493n;
  const D2 = (2n * D) % P;
  const II = modPow(2n, (P - 1n) / 4n, P);

  function modPow(b, e, m) {
    let r = 1n; b %= m;
    while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; }
    return r;
  }
  // JS % 对负数保留符号；Ed25519 全程要求 [0,P) 非负余数（与 Python 一致）。
  function mod(a, m) { const r = a % m; return r < 0n ? r + m : r; }
  function xRecover(y) {
    const xx = ((y * y - 1n) * modPow(D * y * y + 1n, P - 2n, P)) % P;
    let x = modPow(xx, (P + 3n) / 8n, P);
    if (mod(x * x - xx, P) !== 0n) x = (x * II) % P;
    if (x & 1n) x = P - x;
    return x;
  }
  const BY = (4n * modPow(5n, P - 2n, P)) % P;
  const BX = xRecover(BY);
  const B = [BX, BY, 1n, (BX * BY) % P];
  const IDENT = [0n, 1n, 1n, 0n];

  function padd(PP, Q) {
    let [X1, Y1, Z1, T1] = PP;
    const [X2, Y2, Z2, T2] = Q;
    const A = mod((Y1 - X1) * (Y2 - X2), P);
    const Bb = mod((Y1 + X1) * (Y2 + X2), P);
    const C = (T1 * D2 * T2) % P;
    const Dd = (Z1 * 2n * Z2) % P;
    const E = mod(Bb - A, P), F = mod(Dd - C, P), G = (Dd + C) % P, H = (Bb + A) % P;
    return [mod(E * F, P), mod(G * H, P), mod(F * G, P), mod(E * H, P)];
  }
  function pdbl(PP) { return padd(PP, PP); }
  function pneg(PP) {
    const [X, Y, Z, T] = PP;
    return [mod(-X, P), Y, Z, mod(-T, P)];
  }
  function peq(PP, Q) {
    return PP[0] * Q[2] % P === Q[0] * PP[2] % P &&
           PP[1] * Q[2] % P === Q[1] * PP[2] % P;
  }
  function pmul(PP, e) {
    let R = IDENT;
    while (e > 0n) { if (e & 1n) R = padd(R, PP); PP = pdbl(PP); e >>= 1n; }
    return R;
  }
  function encodePt(PP) {
    const [X, Y, Z] = PP;
    const zi = modPow(Z, P - 2n, P);
    const x = X * zi % P, y = Y * zi % P;
    const out = new Uint8Array(32);
    let v = (y & ((1n << 255n) - 1n)) | ((x & 1n) << 255n);
    for (let i = 0; i < 32; i++) { out[i] = Number(v & 0xffn); v >>= 8n; }
    return out;
  }
  function leBytesToBig(u8) {
    let v = 0n;
    for (let i = u8.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(u8[i]);
    return v;
  }
  function scalarOf(seed) {
    // sync sha512 needed inside key derivation; exposed via sha512Sync on Node,
    // browser path awaits in async wrappers.
    const h = sha512Sync(seed);
    let a = leBytesToBig(h.subarray(0, 32));
    a &= (1n << 254n) - 8n;
    a |= 1n << 254n;
    return [a, h];
  }
  function sha512Sync(bytes) {
    if (!nodeCrypto) throw new Error("sync sha512 only in node");
    return nodeCrypto.createHash("sha512").update(Buffer.from(bytes)).digest();
  }
  function hint(b) { return leBytesToBig(sha512Sync(b)); }
  function decPt(s) {
    if (s.length !== 32) throw new Error("bad point");
    let y = leBytesToBig(s) & ((1n << 255n) - 1n);
    let x = xRecover(y);
    if ((x & 1n) !== BigInt((s[31] >> 7) & 1)) x = P - x;
    if (mod(-x * x + y * y - 1n - D * x * x * y * y, P) !== 0n) throw new Error("off curve");
    return [x, y, 1n, (x * y) % P];
  }

  // ---------- 同步实现（Node 测试用） ----------
  function publicFromSeedSync(seed) {
    const [a] = scalarOf(seed);
    return encodePt(pmul(B, a));
  }
  function signSync(seed, msg) {
    const [a, h] = scalarOf(seed);
    const pub = encodePt(pmul(B, a));
    const r = hint(concat(h.subarray(32), msg)) % L;
    const Rb = encodePt(pmul(B, r));
    const S = (r + hint(concat(concat(Rb, pub), msg)) * a) % L;
    const Sb = new Uint8Array(32);
    let v = S;
    for (let i = 0;i < 32; i++) { Sb[i] = Number(v & 0xffn); v >>= 8n; }
    return b64e(concat(Rb, Sb));
  }
  function verifySync(publicHex, msg, sigB64) {
    try {
      const pk = hexToBytes(publicHex);
      const sig = b64d(sigB64);
      if (sig.length !== 64) return false;
      const R = decPt(sig.subarray(0, 32));
      const A = decPt(pk);
      const S = leBytesToBig(sig.subarray(32));
      if (S >= L) return false;
      const h = hint(concat(concat(sig.subarray(0, 32), pk), msg)) % L;
      let Q = IDENT;
      const nA = pneg(A);
      for (let i = 254; i >= 0; i--) {
        Q = pdbl(Q);
        if ((S >> BigInt(i)) & 1n) Q = padd(Q, B);
        if ((h >> BigInt(i)) & 1n) Q = padd(Q, nA);
      }
      return peq(padd(Q, pneg(R)), IDENT);
    } catch { return false; }
  }

  function concat(a, b) {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0); out.set(b, a.length);
    return out;
  }
  function hexToBytes(hex) {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }
  function bytesToHex(u8) {
    return [...u8].map((x) => x.toString(16).padStart(2, "0")).join("");
  }
  function randomSeed() {
    const b = new Uint8Array(32);
    if (nodeCrypto) nodeCrypto.webcrypto.getRandomValues(b);
    else crypto.getRandomValues(b);
    return b;
  }

  // ---------- 异步 API（浏览器与 Node 通用） ----------
  // 浏览器没有同步 SHA-512，因此把 scalar 推导也做成 await 版本。
  async function sha512Async(bytes) { return new Uint8Array(await sha512(bytes)); }
  async function scalarOfAsync(seed) {
    const h = await sha512Async(seed);
    let a = leBytesToBig(h.subarray(0, 32));
    a &= (1n << 254n) - 8n;
    a |= 1n << 254n;
    return [a, h];
  }
  function hintSyncFromHash(h) { return leBytesToBig(h); }

  async function generateKey() {
    const seed = randomSeed();
    const [a] = await scalarOfAsync(seed);
    const pub = encodePt(pmul(B, a));
    const publicHex = bytesToHex(pub);
    const secretHex = bytesToHex(seed);
    return {
      publicHex,
      secretHex,
      exportSecret() { return secretHex; },
    };
  }
  async function sign(secretHex, msg) {
    const seed = hexToBytes(secretHex);
    const [a, h] = await scalarOfAsync(seed);
    const pub = encodePt(pmul(B, a));
    const hr = await sha512Async(concat(h.subarray(32), msg));
    const r = leBytesToBig(hr) % L;
    const Rb = encodePt(pmul(B, r));
    const hk = await sha512Async(concat(concat(Rb, pub), msg));
    const S = (r + leBytesToBig(hk) * a) % L;
    const Sb = new Uint8Array(32);
    let v = S;
    for (let i = 0; i < 32; i++) { Sb[i] = Number(v & 0xffn); v >>= 8n; }
    return b64e(concat(Rb, Sb));
  }
  async function verify(publicHex, msg, sigB64) {
    try {
      const pk = hexToBytes(publicHex);
      const sig = b64d(sigB64);
      if (sig.length !== 64 || pk.length !== 32) return false;
      const R = decPt(sig.subarray(0, 32));
      const A = decPt(pk);
      const S = leBytesToBig(sig.subarray(32));
      if (S >= L) return false;
      const hh = await sha512Async(concat(concat(sig.subarray(0, 32), pk), msg));
      const h = leBytesToBig(hh) % L;
      let Q = IDENT;
      const nA = pneg(A);
      for (let i = 254; i >= 0; i--) {
        Q = pdbl(Q);
        if ((S >> BigInt(i)) & 1n) Q = padd(Q, B);
        if ((h >> BigInt(i)) & 1n) Q = padd(Q, nA);
      }
      return peq(padd(Q, pneg(R)), IDENT);
    } catch { return false; }
  }

  return {
    canonicalBytes, canonical, digestHex, b64e, b64d, hexToBytes, bytesToHex,
    generateKey, sign, verify,
    // Node 同步变体（跨语言互通测试）
    _sync: { publicFromSeedSync, signSync, verifySync, canonicalBytes },
  };
});
