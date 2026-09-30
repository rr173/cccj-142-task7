"""设备可信证明层（零外部依赖，Python 标准库）。

修复要点：主体端 / 站点端 / 外部见证链接这三个办理入口的任何状态变更，都必须绑定
本站点一台已登记、未隔离、证书在有效期内且为当前代次的终端设备证明：

  1. 浏览器本机生成 Ed25519 终端密钥（私钥不出设备），凭现场管理员签发的一次性注册码
     完成登记，服务端用签发根密钥签发绑定 机构/设备标识/可用角色/有效期/代次 的证书；
  2. 每次落款/撤销/执行确认前先领取服务端签名的短时挑战，挑战钉死
     动作/会话/角色/内容指纹/机构/截止时间；终端用本机私钥对完整请求签名后提交；
  3. 服务端在**同一笔 BEGIN IMMEDIATE 业务事务**内核对证书、挑战、请求绑定、代次、
     隔离状态并消费随机数——凭据核验与业务落盘原子绑定，不存在"业务成功、设备无留痕"
     或崩溃后生成第二次变更的窗口。

密码学：纯 Python Ed25519（RFC 8032，标准库 hashlib 实现，无第三方依赖）。
终端（浏览器侧）对应实现见 static/shared/ed25519.js，两端规范化字节一致。
"""
import base64
import hashlib
import json
import secrets
import time

# 算法标识（信封自描述，便于将来升级代次/算法）
TERM_ALG = "CT-TERM-ED25519/v1"      # 终端证书
CA_ALG = "CT-CA-ED25519/v1"          # 服务端签发根
CHALLENGE_ALG = "CT-CHALLENGE/v1"
REQUEST_ALG = "CT-SIGN-REQUEST/v1"

# 业务动作 -> 可落款角色（办理语义角色）
ACTION_ROLES = {
    "sign": ("subject", "witness", "site_owner"),
    "revoke": ("subject",),
    "execute": ("site",),
}
# 设备证书角色 -> 可代表的落款角色。现场设备（site）代表现场负责人（site_owner）落款。
DEVICE_ROLE_SIGN_ROLES = {
    "subject": ("subject",),
    "witness": ("witness",),
    "site": ("site_owner", "site"),
}
KNOWN_DEVICE_ROLES = ("subject", "witness", "site")


def device_role_may_sign(device_role, sign_role):
    return sign_role in DEVICE_ROLE_SIGN_ROLES.get(device_role, ())


# ============================================================ 规范化 JSON
def canonical_bytes(obj):
    """两端字节一致的规范 JSON：键排序、无空白、紧凑分隔符、不转义非 ASCII。"""
    return json.dumps(
        obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def digest_hex(obj):
    return hashlib.sha256(canonical_bytes(obj)).hexdigest()


def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64d(txt: str) -> bytes:
    pad = "=" * (-len(txt) % 4)
    return base64.urlsafe_b64decode(txt + pad)


# ============================================================ Ed25519（纯 Python）
_p = 2 ** 255 - 19
_d = (-121665 * pow(121666, _p - 2, _p)) % _p
_L = 2 ** 252 + 27742317777372353535851937790883648493
_d2 = (2 * _d) % _p
_II = pow(2, (_p - 1) // 4, _p)


def _xrecover(y):
    xx = (y * y - 1) * pow(_d * y * y + 1, _p - 2, _p)
    x = pow(xx, (_p + 3) // 8, _p)
    if (x * x - xx) % _p:
        x = x * _II % _p
    if x & 1:
        x = _p - x
    return x


_By = (4 * pow(5, _p - 2, _p)) % _p
_Bx = _xrecover(_By)
_B = (_Bx, _By, 1, _Bx * _By % _p)
_IDENT = (0, 1, 1, 0)


def _add(P, Q):
    X1, Y1, Z1, T1 = P
    X2, Y2, Z2, T2 = Q
    A = (Y1 - X1) * (Y2 - X2) % _p
    Bb = (Y1 + X1) * (Y2 + X2) % _p
    C = T1 * _d2 * T2 % _p
    Dd = Z1 * 2 * Z2 % _p
    E = Bb - A
    F = Dd - C
    G = Dd + C
    H = Bb + A
    return (E * F % _p, G * H % _p, F * G % _p, E * H % _p)


def _dbl(P):
    return _add(P, P)  # 与仿射参考逐点核对过的加法；加倍即自加


def _neg(P):
    X, Y, Z, T = P
    return ((-X) % _p, Y, Z, (-T) % _p)


def _eq(P, Q):
    return (P[0] * Q[2] % _p == Q[0] * P[2] % _p and
            P[1] * Q[2] % _p == Q[1] * P[2] % _p)


def _mul(P, e):
    R = _IDENT
    while e:
        if e & 1:
            R = _add(R, P)
        P = _dbl(P)
        e >>= 1
    return R


def _encode_pt(P):
    X, Y, Z, _ = P
    zi = pow(Z, _p - 2, _p)
    x = X * zi % _p
    y = Y * zi % _p
    return ((y & ((1 << 255) - 1)) | ((x & 1) << 255)).to_bytes(32, "little")


def _scalar_of(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h


def _hint(b):
    return int.from_bytes(hashlib.sha512(b).digest(), "little")


def _decode_pt(s):
    if len(s) != 32:
        raise ValueError("bad point length")
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if (x & 1) != (s[31] >> 7):
        x = _p - x
    if (-x * x + y * y - 1 - _d * x * x * y * y) % _p:
        raise ValueError("point not on curve")
    return (x, y, 1, x * y % _p)


class DeviceKey:
    """Ed25519 终端/签发密钥。公钥为 32 字节小写 hex；私钥种子 32 字节，仅本机持有。"""

    def __init__(self, seed: bytes, public: bytes = None):
        self.seed = bytes(seed)
        a, _h = _scalar_of(self.seed)
        self._a = a
        self.public = public if public is not None else _encode_pt(_mul(_B, a))

    @staticmethod
    def generate():
        return DeviceKey(secrets.token_bytes(32))

    @property
    def public_hex(self):
        return self.public.hex()

    def sign(self, msg: bytes) -> str:
        _, h = _scalar_of(self.seed)
        r = _hint(h[32:] + msg) % _L
        Rb = _encode_pt(_mul(_B, r))
        S = (r + _hint(Rb + self.public + msg) * self._a) % _L
        return b64e(Rb + S.to_bytes(32, "little"))

    @staticmethod
    def verify(public_hex, msg: bytes, sig_b64: str) -> bool:
        try:
            pk = bytes.fromhex(public_hex)
            sig = b64d(sig_b64)
            if len(sig) != 64:
                return False
            R = _decode_pt(sig[:32])
            A = _decode_pt(pk)
            S = int.from_bytes(sig[32:], "little")
            if S >= _L:
                return False
            h = _hint(sig[:32] + pk + msg) % _L
            P = _IDENT
            nA = _neg(A)
            for i in range(254, -1, -1):
                P = _dbl(P)
                if (S >> i) & 1:
                    P = _add(P, _B)
                if (h >> i) & 1:
                    P = _add(P, nA)
            return _eq(_add(P, _neg(R)), _IDENT)
        except Exception:
            return False


def sign_canonical(key: DeviceKey, obj) -> str:
    return key.sign(canonical_bytes(obj))


def verify_canonical(public_hex, obj, sig_b64) -> bool:
    return DeviceKey.verify(public_hex, canonical_bytes(obj), sig_b64)


# ============================================================ 签发根密钥
def generate_server_keypair():
    """服务端签发根密钥（首启生成、随库持久化；用于签发证书/挑战与记录信封）。"""
    key = DeviceKey.generate()
    return {
        "alg": CA_ALG,
        "public_hex": key.public_hex,
        "seed_hex": key.seed.hex(),
    }


# ============================================================ 证书 / 挑战 / 请求信封
def issue_certificate(server_key: DeviceKey, cert: dict) -> dict:
    """cert 字段：cert_id/device_id/inst_id/device_label/roles/gen/not_before/not_after/public_hex。"""
    payload = {**cert, "alg": TERM_ALG}
    return {"payload": payload, "signature": sign_canonical(server_key, payload)}


def parse_certificate(envelope, server_public_hex: str, now_ms: int):
    """仅做：结构、服务端签名、有效期。返回 payload；不合法返回 None。

    代次/隔离属于业务状态，由引擎在事务内另查（核验与业务落盘同一事务）。
    """
    if not isinstance(envelope, dict):
        return None
    p = envelope.get("payload")
    sig = envelope.get("signature")
    if not isinstance(p, dict) or not isinstance(sig, str):
        return None
    if p.get("alg") != TERM_ALG:
        return None
    if not verify_canonical(server_public_hex, p, sig):
        return None
    try:
        if int(p["not_before_ms"]) > now_ms or int(p["not_after_ms"]) <= now_ms:
            return None
    except (KeyError, TypeError, ValueError):
        return None
    return p


def issue_challenge(server_key: DeviceKey, ch: dict) -> dict:
    payload = {**ch, "alg": CHALLENGE_ALG}
    return {"challenge": payload, "signature": sign_canonical(server_key, payload)}


def signing_request(challenge: dict, terminal_sig: str = None) -> dict:
    """被终端私钥签署的完整请求：包含挑战全部绑定字段与挑战服务端签名。

    替换动作/会话/角色/内容指纹/机构/随机数/证书/截止时间任一字段都会使签名失配。
    """
    return {
        "alg": REQUEST_ALG,
        "cert_id": challenge["cert_id"],
        "nonce": challenge["nonce"],
        "action": challenge["action"],
        "session_id": challenge["session_id"],
        "role": challenge["role"],
        "body_digest": challenge["body_digest"],
        "inst_id": challenge["inst_id"],
        "challenge_sig": challenge["challenge_sig"],
    }


def request_fingerprint(sreq: dict) -> str:
    """幂等落点：只含被签署内容，不含含随机因子的终端签名编码本身。

    因此两个标签页对同一挑战各自独立签名也判同一请求，返回同一份首次回执。
    """
    return digest_hex(sreq)


def now_ms():
    return int(time.time() * 1000)
