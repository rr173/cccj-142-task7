/*
 * 浏览器侧 Ed25519（static/shared/ed25519.js）与服务端 device.py 的字节级一致性。
 *
 * 本文件只跑 Node 同步变体（_sync），断言：
 *  - RFC 8032 测试向量（公钥/签名）；
 *  - 自签自验 + 篡改检出；
 *  - canonical JSON 与 Python 输出逐字节相同（VEC_* 由 tests/ed_vectors.py 重新生成并打印，
 *    两者来源一致；这里硬编码 canonical 十六进制做回归锚点）。
 * 运行：node tests/ed25519_parity.test.js
 */
const test = require("node:test");
const assert = require("node:assert");
const path = require("node:path");
const CT = require(path.join(__dirname, "..", "static", "shared", "ed25519.js"));
const s = CT._sync;

test("RFC 8032 向量1：空消息公钥与签名", () => {
  const seed = Buffer.from(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "hex");
  const pub = Buffer.from(s.publicFromSeedSync(seed)).toString("hex");
  assert.strictEqual(pub,
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
  const sigHex = Buffer.from(CT.b64d(s.signSync(seed, Buffer.alloc(0)))).toString("hex");
  assert.strictEqual(sigHex,
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
});

test("RFC 8031 向量2：单字节 0x72", () => {
  const seed = Buffer.from(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "hex");
  assert.strictEqual(Buffer.from(s.publicFromSeedSync(seed)).toString("hex"),
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
  const sigHex = Buffer.from(CT.b64d(s.signSync(seed, Buffer.from([0x72])))).toString("hex");
  assert.strictEqual(sigHex,
    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
    "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
});

test("自签自验 + 篡改/异文检出", () => {
  const nodeCrypto = require("node:crypto");
  const seed = nodeCrypto.randomBytes(32);
  const pub = Buffer.from(s.publicFromSeedSync(seed)).toString("hex");
  const msg = nodeCrypto.randomBytes(48);
  const sig = s.signSync(seed, msg);
  assert.ok(s.verifySync(pub, msg, sig));
  assert.ok(!s.verifySync(pub, Buffer.concat([msg, Buffer.from("x")]), sig));
  const bad = Buffer.from(sig, "utf8"); // not b64 of a valid sig
  assert.ok(!s.verifySync(pub, msg, "AAAA"));
});

test("canonical JSON 锚点与 Python device.canonical_bytes 一致", () => {
  const obj = {
    action: "sign", alg: "CT-SIGN-REQUEST/v1",
    body_digest: "0".repeat(64), cert_id: "C-9", challenge_sig: "SIG",
    inst_id: "INST-A", nonce: "abc", role: "subject", session_id: "S-9",
  };
  // 由 `python -c "import device;print(device.canonical_bytes(obj).hex())"` 固定
  const expected = "7b22616374696f6e223a227369676e222c22616c67223a2243542d5349474e2d524551554553542f7631222c22626f64795f646967657374223a2230303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030222c22636572745f6964223a22432d39222c226368616c6c656e67655f736967223a22534947222c22696e73745f6964223a22494e53542d41222c226e6f6e6365223a22616263222c22726f6c65223a227375626a656374222c2273657373696f6e5f6964223a22532d39227d";
  assert.strictEqual(Buffer.from(s.canonicalBytes(obj)).toString("hex"), expected);
});

test("同密钥同消息签名确定性可验（Ed25519 确定性，JS/Python 同字节）", () => {
  const seed = Buffer.from(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "hex");
  const pub = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
  const obj = {
    action: "sign", alg: "CT-SIGN-REQUEST/v1", body_digest: "0".repeat(64),
    cert_id: "C-9", challenge_sig: "SIG", inst_id: "INST-A",
    nonce: "abc", role: "subject", session_id: "S-9",
  };
  const msg = s.canonicalBytes(obj);
  const sig = s.signSync(seed, msg);
  // 该值与 `device.DeviceKey(seed).sign(device.canonical_bytes(obj))` 完全一致
  assert.strictEqual(sig,
    "6uH0i1ldegB_0E1P57P2jQWIKN3UL2dQkjk9MTqepjpTf59WxKvzFo5TgnoeJSXg-wydnk-hN82XKkc7MCwoCw");
  assert.ok(s.verifySync(pub, msg, sig));
});
