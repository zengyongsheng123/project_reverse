# -*- coding: utf-8 -*-
"""
京东 h5st 5.3 纯 Python 实现（逆向自 js_security_v3_0.1.4.js，经 JSVMP 日志插桩逐字段验证）

h5st 结构（10 个分号分隔字段）:
  ts17;fp;appId;token;signStr(f5);5.3;t;envB64(f8);signedStr(f9);stkB64(f10)

关键算法（全部经 VM 插桩 trace 验证，见 recon/vm_trace.txt）:
  token/rd: POST https://cactus.jd.com/request_algo 由服务端下发（get_token_rd）
            rd 自造会验签失败（HTTP 403），必须使用该接口返回值
  keystr   = token + fp + ts17 + "52" + appId + salt + "=@3k4k"
  salt     = rd(12字符) + passB(9字符)
               passB[j] = ALPHA2[(3*sum(ord(c) for c in s[blk*j:blk*(j+1)])) % 64]
               s   = token+fp+ts17+"52"+appId+rd, blk = len(s)//9
  keyhex   = swap7(sha256(keystr).digest()).hex()      # swap7: 前7字节反转
  iKey     = SBOX(reverse(keyhex[:16])) ^ 0x36 || keyhex[16:] ^ 0x36
  oKey     = iKey ^ 0x6a
  f5/f9    = swap7(sha256(oKey + sha256(iKey + msg)).digest()).hex()
             msg5 = se1(se1(paramsStr)[:-2]) + "=@3k4k"
             msg9 = se1(se1("appid:appid&functionId:functionid")[:-2]) + "=@3k4k"
  se1(m)   = m + 9 个校验字符: 分成 9 块, 每块字符和 *3 % 64 查 ALPHA2
  f8/f10   = 自定义 base64: 3字节→4字符(短尾组用 B64MAP[缺失数]补齐), 整体反转
  ts17     = yyyyMMddHHmmssSSS（东八区）, 且恒等于 t + 3000ms
"""
import hashlib
import json
import os
import random
import sys
import time

from loguru import logger

# 日志: 控制台 INFO + 文件 DEBUG（按天轮转）
os.makedirs("logs", exist_ok=True)
try:
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass
logger.remove()
logger.add(sys.stderr, level="INFO",
           format="<green>{time:HH:mm:ss}</green> | <level>{level: <7}</level> | {message}")
logger.add("logs/h5st_{time:YYYY-MM-DD}.log", level="DEBUG", rotation="1 day", retention="7 days",
           encoding="utf-8", enqueue=True)

ALPHA2 = "nmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA-_9876543210zyxwvutsrqpo"
B64MAP = "rqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA-_9876543210zyxwvuts"
SBOX = {'0': 'e', '1': 'l', '2': 's', '3': 'z', '4': '"', '5': ')', '6': '0', '7': '7',
        '8': '>', '9': 'E', 'a': '@', 'b': 'G', 'c': 'N', 'd': 'U', 'e': '\\', 'f': 'c'}

VERSION = "5.3"
APP_ID = "b5216"          # h5st 字段 3 (pc 首页签名 appId)
APPID = "www-jd-com"      # 请求参数 appid


def swap7(d: bytes) -> bytes:
    """前 7 字节反转（JD 自定义哈希后处理）"""
    return d[6::-1] + d[7:]


def se1(msg: str) -> str:
    """_seData1: 尾部追加 9 个由分块字符和生成的校验字符"""
    L = len(msg)
    g = L // 9
    out = []
    for j in range(8):
        out.append(ALPHA2[(3 * sum(map(ord, msg[j * g:(j + 1) * g]))) % 64])
    out.append(ALPHA2[(3 * sum(map(ord, msg[8 * g:]))) % 64])
    return msg + ''.join(out)


def custom_b64(data: bytes) -> str:
    """f8/f10 自定义 base64：每 3 字节 4 字符，尾组用 B64MAP[缺失字节数] 补齐，整体反转"""
    out = []
    n = len(data)
    for i in range(0, n, 3):
        ch = data[i:i + 3]
        v = int.from_bytes(ch.ljust(3, b'\x00'), 'big')
        chars = [B64MAP[(v >> 18) & 63], B64MAP[(v >> 12) & 63],
                 B64MAP[(v >> 6) & 63], B64MAP[v & 63]]
        missing = 3 - len(ch)
        if missing:
            chars[3] = B64MAP[missing]
        out.append(''.join(chars))
    return ''.join(out)[::-1]


def gen_salt(token: str, fp: str, ts17: str, app_id: str, rd: str) -> str:
    """salt = rd(12) + 9 个 ALPHA2 字符（对 token+fp+ts17+'52'+appId+rd 分块求和）"""
    s = token + fp + ts17 + "52" + app_id + rd
    blk = len(s) // 9
    tail = ''.join(ALPHA2[(3 * sum(map(ord, s[blk * j:blk * (j + 1)]))) % 64]
                   for j in range(9))
    return rd + tail


def derive_ikey_okey(keystr: str):
    keyhex = swap7(hashlib.sha256(keystr.encode()).digest()).hex()
    first = ''.join(SBOX[c] for c in keyhex[:16][::-1]).encode()
    i_key = bytes(b ^ 0x36 for b in first) + bytes(b ^ 0x36 for b in keyhex[16:].encode())
    o_key = bytes(b ^ 0x6a for b in i_key)
    return i_key, o_key


def custom_mac(i_key: bytes, o_key: bytes, msg: bytes) -> str:
    inner = hashlib.sha256(i_key + msg).digest()
    return swap7(hashlib.sha256(o_key + inner).digest()).hex()


def _ts17(ms: int) -> str:
    """yyyyMMddHHmmssSSS（东八区）"""
    t = time.gmtime(ms / 1000.0 + 8 * 3600)
    return time.strftime("%Y%m%d%H%M%S", t) + "%03d" % (ms % 1000)


def _rand(n: int, alphabet: str = "abcdefghijklmnopqrstuvwxyz0123456789") -> str:
    return ''.join(random.choice(alphabet) for _ in range(n))


def build_env(fp: str, ms: int) -> str:
    """f8 明文 env JSON（字段格式与 js_security 采集一致）"""
    env = (
        '{\n'
        '  "sua": "Windows NT 10.0; Win64; x64",\n'
        '  "pp": {},\n'
        '  "extend": {\n'
        '    "wd": 0,\n'
        '    "l": 0,\n'
        '    "ls": 5,\n'
        '    "wk": 64,\n'
        '    "bu1": "0.1.4",\n'
        '    "bu3": 43,\n'
        '    "bu4": 0,\n'
        '    "bu5": 0,\n'
        '    "bu6": 29,\n'
        '    "bu7": 0,\n'
        '    "bu8": 0,\n'
        '    "random": "%s",\n'
        '    "bu12": -8,\n'
        '    "bu10": 14,\n'
        '    "bu11": 4,\n'
        '    "bu13": "Aj,F1,Al"\n'
        '  },\n'
        '  "pf": "Win32",\n'
        '  "random": "%s",\n'
        '  "v": "h5_file_v5.3.5",\n'
        '  "bu4": "0",\n'
        '  "canvas": "%s",\n'
        '  "webglFp": "%s",\n'
        '  "ccn": 16,\n'
        '  "bu14": "%s",\n'
        '  "t": %d,\n'
        '  "fp": "%s"\n'
        '}'
    ) % (_rand(10, ALPHA2), _rand(11, ALPHA2), hashlib.md5(_rand(32).encode()).hexdigest(),
         hashlib.md5(_rand(32).encode()).hexdigest(), _rand(10, ALPHA2), ms, fp)
    return env


def sign(function_id: str, body: str, token: str, fp: str = None, app_id: str = APP_ID,
         appid: str = APPID, client: str = "pc", client_version: str = "1.0.0",
         rd: str = None, ms: int = None):
    """
    生成完整 h5st。
    token: tk03 开头的会话 token（必须有效，经 get_token_rd 获取）
    fp:    16 位随机指纹；None 则自动生成
    rd:    12 位盐前缀；None 则自动生成。注意：线上验签要求 rd 为
           request_algo 服务端下发的值（用 get_token_rd 获取），自造 rd 会 403
    ms:    毫秒时间戳；None 则取当前时间
    返回 dict: h5st / t / body_hash / _stk / keystr / salt / fp / rd / f5 / f9
    """
    if fp is None:
        fp = _rand(16)
    if rd is None:
        rd = _rand(12, ALPHA2)
        logger.warning("rd 为本地随机生成；线上请求请改用 get_token_rd() 获取服务端 rd，否则验签失败")
    if ms is None:
        ms = int(time.time() * 1000)

    ts17 = _ts17(ms + 3000)  # ts17 恒为 t+3000ms（经 8 组样本验证偏移恰为 3000）

    pairs = {
        "appid": appid,
        "body": hashlib.sha256(body.encode()).hexdigest(),
        "client": client,
        "clientVersion": client_version,
        "functionId": function_id,
        "t": str(ms),
    }
    params_str = '&'.join(f"{k}:{pairs[k]}" for k in sorted(pairs))
    stk = ','.join(sorted(pairs))

    salt = gen_salt(token, fp, ts17, app_id, rd)
    keystr = token + fp + ts17 + "52" + app_id + salt + "=@3k4k"
    i_key, o_key = derive_ikey_okey(keystr)

    msg5 = se1(se1(params_str)[:-2]) + "=@3k4k"
    f5 = custom_mac(i_key, o_key, msg5.encode())

    msg9 = se1(se1("appid:appid&functionId:functionid")[:-2]) + "=@3k4k"
    f9 = custom_mac(i_key, o_key, msg9.encode())

    f8 = custom_b64(build_env(fp, ms).encode())
    f10 = custom_b64(stk.encode())

    h5st = ';'.join([ts17, fp, app_id, token, f5, VERSION, str(ms), f8, f9, f10])
    logger.debug(f"sign: ts17={ts17} t={ms} fp={fp} rd={rd}\n  salt={salt}\n  keystr={keystr}\n"
                 f"  f5={f5}\n  f9={f9}\n  f10={f10}")
    return {
        "h5st": h5st,
        "t": str(ms),
        "body": body,
        "body_hash": pairs["body"],
        "_stk": stk,
        "keystr": keystr,
        "salt": salt,
        "fp": fp,
        "rd": rd,
        "f5": f5,
        "f9": f9,
    }


def get_token_rd(session, fp: str, app_id: str = APP_ID):
    """
    从京东签名服务换取 (token, rd)。
    rd 由服务端下发（藏在返回的 algo 函数字符串中），签名密钥依赖它，
    必须由本接口获取，不能自造 —— 否则 f5/f9 验签失败（HTTP 403/605）。

    session: requests/curl_cffi 会话（自带 cookies 与 UA）
    返回 (token, rd)
    """
    payload = {"version": VERSION, "fp": fp, "appId": app_id,
               "timestamp": int(time.time() * 1000), "platform": "web"}
    r = session.post(
        "https://cactus.jd.com/request_algo",
        headers={"content-type": "application/json", "origin": "https://www.jd.com",
                 "referer": "https://www.jd.com/"},
        data=json.dumps(payload), timeout=15)
    res = r.json()["data"]["result"]
    rd = res["algo"].split("rd='")[1].split("'")[0]
    logger.info(f"request_algo ok: token={res['tk'][:30]}... rd={rd}")
    logger.debug(f"request_algo payload={payload} resp_ts={res.get('ts')}")
    return res["tk"], rd


if __name__ == "__main__":
    # 用历史 trace 数据自测（冻结时间戳，与插桩 trace 真值逐字段比对）
    r = sign(
        function_id="pc_home_feed",
        body='{"page":1,"pagesize":25,"area":"","source":"pc-home","kuangjia":1,"notJsonp":true}',
        token="tk03wdf5b1c6018nRRwmgicnmY0yOauuDBb1hI_a8zJlqOTmMcdAfev_C7heTpuMftKiQH1X64N69QYS8I96cm1IUUOa",
        fp="zpypppbpyjimapb2",
        rd="a9B0qDgOvNcZ",
        ms=1789825017983,
    )
    print("salt:", r["salt"], "(expect a9B0qDgOvNcZmROhryZgV)")
    print("f9  :", r["f9"], "(expect 653ac1cd9fa7be96a90bb9c1d50b94a5dba2591e2a6505e78b8221b326c46c4e)")
    print("f10 :", r["h5st"].split(";")[-1])
    print("(expect qbkgHGHQ8GlOIyVOF6JQ8G1P5WFW3yVSC61T-bEQGGlQI6ZNHuFT-bVR7qUT)")
