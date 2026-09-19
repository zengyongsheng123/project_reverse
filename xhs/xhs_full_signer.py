import base64
import hashlib
import json
import os
import random
import struct
import sys
import time
from dataclasses import dataclass
from typing import Any, Optional, Union
from urllib.parse import quote, urlparse

import requests
from loguru import logger

# 外层 XYS_ 和 x-s-common 使用这个自定义 Base64 字符表。
CUSTOM_BASE64_ALPHABET = "ZmserbBoHQtNP+wOcza/LpngG8yJq42KWYj0DSfdikx3VT16IlUAFM97hECvuRX5"
# mns0301_ 的 x3 内层还有一套独立 Base64 字符表。
X3_BASE64_ALPHABET = "MfgqrsbcyzPQRStuvC7mn501HIJBo2DEFTKdeNOwxWXYZap89+/A4UVLhijkl63G"
STANDARD_BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
# 从 mnsv2 wasm 路径还原出的静态异或密钥。
HEX_KEY = (
    "71a302257793271ddd273bcee3e4b98d9d7935e1da33f5765e2ea8afb6dc77a5"
    "1a499d23b67c20660025860cbf13d4540d92497f58686c574e508f46e195634"
    "4f39139bf4faf22a3eef120b79258145b2feb5193b6478669961298e79bedc"
    "a646e1a693a926154a5a7a1bd1cf0dedb742f917a747a1e388b234f2277"
    "516db7116035439730fa61e9822a0eca7bff72d8"
)
VERSION_BYTES = [121, 104, 96, 41]
ENV_TABLE = [115, 248, 83, 102, 103, 201, 181, 131, 99, 94, 4, 68, 250, 132, 21]
ENV_CHECKS_DEFAULT = [0, 1, 18, 1, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0]
HASH_IV = (1831565813, 461845907, 2246822507, 3266489909)
A3_PREFIX = [2, 97, 51, 16]
PAYLOAD_LENGTH = 144
# x-s-common 的状态种子串，x9 由下面的 CRC 变体基于它计算。
X_S_COMMON_SEED = 'I38rHdgsjopgIvesdVwgIC+oIELmBZ5e3VwXLgFTIxS3bqwErFeexd0ekncAzMFYnqthIhJeSnMDKutRI3KsYorWHPtGrbV0P9WfIi/eWc6eYqtyQApPI37ekmR6QL+5Ii6sdneeSfqYHqwl2qt5B0DBIx+PGDi/sVtkIxdsxuwr4qtiIhuaIE3e3LV0I3VTIC7e0utl2ADmsLveDSKsSPw5IEvsiVtJOqw8BuwfPpdeTFWOIx4TIiu6ZPwrPut5IvlaLbgs3qtxIxes1VwHIkumIkIyejgsY/WTge7eSqte/D7sDcpipedeYrDtIC6eDVw2IENsSqtlnlSuNjVtIvoekqt3cZ7sVo4gIESyIhEJ+9DUIvzy4I8OIic7ZPwUIvih4o/sDLds6PwVIC7eSd7s69ImIh6s3zrdQut5IEos3j5exLJsVPwcr9gsSPtxICMPLgoefuw5zn5sWVwrI3S2I3T3Bqw+aqwqBjWLJFOsD0OexutmIkJeYa/sx/QBIvOe6e5eWlRrIvNsDqwHIkHiwPwLNVt6I3OeiutdIEAsiqwlIh/eDqtANuwPmVwDIxmxIvQpPdIRJLve3qthIEDaIk0eYuwQZbEqn00sjeHSIEYKPVwQsutaIkJeVPwDKWgskY/e6bEyIEJekd/skqtsnPwqIvgejqwAIkgexjRwIveeS7/efVtSI37skqwuNdRPIhHpICgsxMgeka/eYD6sYPtQIiFRIvcaqVwTI3IBIi3e1AmrgfNeWuwGIxhZyVw+eDge6I6sVPtIePwpIiidIipZoVt7eqw5Ikgs6egeDuwi4qtxICb0QPwYIxWCwaq4Ik5s673sDdgexuwbHqt9IiHmIx6sjVtYIE6eSrFlIxWr/MkkIvRJIvJekqw5Gqt2PqtCIiuZIEJsVUveYuwCcpZvICh4Jut5ePt2Ixq4I3bqIi+EIkgsTYeekZpwwVwpICq1cuwIrVwlIhKe3fPhIiVbp93eiPtVBVtLoahrZ7V0Ik4CguwlIxOs6I8bI3QymqwSIxpnPut+HVtKICPqICkMIv4ueVw9IkZaIhOs6Vw/OYReIvImICosfS7skPwAICYlICLDpYifIhl0LYr9IhesVLoe6Pw9Ih7skVttIvVLICJs0uwZIhQnmPwlIC/sVmImgutlePt/IvKefVtnIvNs1Sz/IC7sYFNsxqtRQ0/sfPwyBLJs0Pt8IxOsTZKe6VttIEi3Ii+vQqwsm0+CIi5exPwMPcge0smGHutkIim9Ix5sVj+iIkKeiPtRICW9IC5eDpPfIERgIiDw8DPpIC/sDFS9IhI9Ixr0IvdsVz8rNqtRnPtZBeKeWmJeYVw6IC3sSZOsTPtrzVtnIxl4butjnuwNJuwxwutDGPwj2noe1zeekBKsiYNekqwnIhuPIkz0IviTICvek76e6arAQVwBIiFnzPtnPoOsVPwmI36edzgsdgbwIxOeSuwHKbGWIv3eSPtFI3Ns1PthJPwoIvAeDdhw2uwNLfoeYMZUIE5sSPttZuw6BeeeiuwucPwqzuwKI3SyIkPUzr3sfIOexqtDIxde3PtZpuw/G/6s1SzRoB4UQckhaVtosVtBIxQfI3GGIvi1tp5eVoMJIxh4ICSOBPwOI3EvJqwtIk5eVchfBPt0IhV4zPtNI35sVY+yIkQvIvgeYuwsLutG/cesY70sDVwaGPwyI38uQVt4IivsfBKef/deTqwJICZgIEee10mbIxOefutgI3LvICKsSPtnGzSHnuwvButLI3qfmPtaIvgsDIde0utwIEgs3junI3/eDpgeYqwyIkYJIv4yc0vsDzJsjVwQIigsWs/s1PtToVt2'
# 可选：保留抓包里的 x-s-common 作为真实请求兜底；置空时会自动动态生成。
CAPTURED_X_S_COMMON = '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'
DEFAULT_URL = 'https://edith.xiaohongshu.com/api/sns/web/v1/homefeed'
DEFAULT_HEADERS = {'accept': 'application/json, text/plain, */*', 'accept-language': 'zh,zh-CN;q=0.9', 'cache-control': 'no-cache', 'content-type': 'application/json;charset=UTF-8', 'origin': 'https://www.xiaohongshu.com', 'pragma': 'no-cache', 'priority': 'u=1, i', 'referer': 'https://www.xiaohongshu.com/', 'sec-ch-ua': '"Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152"', 'sec-ch-ua-mobile': '?0', 'sec-ch-ua-platform': '"Windows"', 'sec-fetch-dest': 'empty', 'sec-fetch-mode': 'cors', 'sec-fetch-site': 'same-site', 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36', 'x-b3-traceid': '8f0d37922911ba5b', 'x-rap-param': 'ByQBBQAAAAEAAAAUAAACBFKrqyMAACg9AAAAGAAAAAAAAAAAcjRuM2jF845Fkqnw2uAGjmI6Us8XAAAAEPxoJ7ieLMjCuxbYL4EYBQC/4/aMzKeHsLd9k5WJjhmh9VD3z0m0UqvR/m0ekshSOcmo1SBf+ddqTs0MxwDbgV4244ryGMOL9pwjCjvHJwR2uj8shMRCcebVrAhWE4YL4p1rDuRBJkPvpPUf1f9QZ3kuoGuFr7cjvuV3GeHFMl7CdVG88sNC1gGHsECO0+EOOvucR+atvonKmfrlOq9GdvfoBb+i6zwtENENhWEpi7sw2l+7DcJ2s3NdwRA8S+auoWJ090Hzd97sYfNyM8xhh+4rcSHq99+bMmguYfFAMxljekeZo2LMHVWSGLQrRfhnPLzwU3Z5ulqpXrQ7dxDM0uChTOlQ6/OP0Q7lr2NlXrphNXx+Hc4qsq1PNASUA6zMFvp0Q/OYdBAoJ2S+1kB+2zBq0hnr6Ht/bn9bA2VqOr4xun/AL/cVKLQFmitSTzFebnjZsmZ3r0aGyM6zVbL3x34H7dnEAxVhi2FXTbLeMsgVhC5odw3Ovu9jTFK9RWSWSBVinSYbF16fyCJFZK9WGru9JMEWe1cJA1qPlFSkJ1U73Fe0L+OI0uzT3IoYJ4ipGNp46kVbRTKVBEPqj2nQA9Kos777ix0U56mEFi9W8tqUWTebaVd+eiChN1DaOjIvQZq2dWeXXsn3j1QBf6uDLOC6NIkqZilDJRINcoonjie4AAAB+A==', 'x-xray-traceid': 'd057674c94d504c5e187704d8e2839a9', 'xy-direction': '46'}
DEFAULT_COOKIES = {'abRequestId': '3b511280-4690-54bf-9930-8b8eef3ea34b', 'ets': '1789626799786', 'webBuild': '6.53.1', 'xsecappid': 'xhs-pc-web', 'a1': '1a0ae11d701s72bhe5a29ljlc3is9cfzvl22ari9h50000383551', 'webId': 'b9cd2253a2e9855e9711fe2a3281b4d3', 'gid': 'y080dyydjyhfy080dyyfW1F38yMWJDxd20JjJjx1V1Sq3J28MjSiu0888qYq22y8yfJ2DKf0', 'web_session': '040069b5953ec4577991aec19e384b056355e6', 'id_token': 'VjEAAM8EPse8sUoXOB4XLN2hdHEvtnF8QNcaUDeWBiyoxNWMSqv1moQwbwyHLmls3JT2XaHB9lg4Rpjrs1mBevQuJtJqagzdG549Y129Rbs6tSe6d/WjQsaT4RryQKre0bHTrCqv', 'x-rednote-datactry': 'CN', 'x-rednote-holderctry': 'CN', 'acw_tc': '0ad587bd17896384368096416e43dda01fb6a78d8b82b2aec942fc4458420a', 'loadts': '1789638950276', 'websectiga': '59d3ef1e60c4aa37a7df3c23467bd46d7f1da0b1918cf335ee7f2e9e52ac04cf', 'sec_poison_id': '19fd3a2f-2d6d-4b62-9f7b-52c28156cbc5', 'unread': '{"ub":"6a9fc76d00000000120014e1","ue":"6aaa2f2c0000000028029aac","uc":15}'}
DEFAULT_BODY = '{"cursor_score":"","num":31,"refresh_type":1,"note_index":35,"unread_begin_note_id":"","unread_end_note_id":"","unread_note_count":0,"category":"homefeed_recommend","search_key":"","need_num":6,"image_formats":["jpg","webp","avif"],"need_filter_image":false}'
_FIRST_VISIT_MS: Optional[int] = None


@dataclass(frozen=True)
class SignState:
    page_load_timestamp: int
    sequence_value: int
    window_props_length: int
    uri_length: int


def setup_logger(level: str = "INFO") -> None:
    logger.remove()
    logger.add(sys.stderr, level=level, format="<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level}</level> | {message}")


def md5_hex(value: str) -> str:
    return hashlib.md5(value.encode("utf-8")).hexdigest()


def _translate_b64(data: Union[bytes, str], alphabet: str) -> str:
    raw = data if isinstance(data, bytes) else data.encode("utf-8")
    encoded = base64.b64encode(raw).decode("ascii")
    return encoded.translate(str.maketrans(STANDARD_BASE64_ALPHABET, alphabet))


def custom_b64_encode(data: Union[bytes, str]) -> str:
    return _translate_b64(data, CUSTOM_BASE64_ALPHABET)


def custom_b64_decode_to_str(data: str) -> str:
    std = data.translate(str.maketrans(CUSTOM_BASE64_ALPHABET, STANDARD_BASE64_ALPHABET))
    return base64.b64decode(std).decode("utf-8")


def x3_b64_encode(data: Union[bytes, bytearray]) -> str:
    return _translate_b64(bytes(data), X3_BASE64_ALPHABET)


def x3_b64_decode(data: str) -> bytes:
    std = data.translate(str.maketrans(X3_BASE64_ALPHABET, STANDARD_BASE64_ALPHABET))
    return base64.b64decode(std)


def _le(value: int, length: int = 4) -> list[int]:
    out = []
    for _ in range(length):
        out.append(value & 0xFF)
        value >>= 8
    return out


def _rol32(value: int, bits: int) -> int:
    return ((value << bits) | (value >> (32 - bits))) & 0xFFFFFFFF


def _custom_hash_v2(input_bytes: list[int]) -> list[int]:
    s0, s1, s2, s3 = HASH_IV
    length = len(input_bytes)
    s0 ^= length
    s1 ^= length << 8
    s2 ^= length << 16
    s3 ^= length << 24
    for i in range(length // 8):
        v0, v1 = struct.unpack("<II", bytes(input_bytes[i * 8 : (i + 1) * 8]))
        s0 = _rol32(((s0 + v0) & 0xFFFFFFFF) ^ s2, 7)
        s1 = _rol32(((v0 ^ s1) + s3) & 0xFFFFFFFF, 11)
        s2 = _rol32(((s2 + v1) & 0xFFFFFFFF) ^ s0, 13)
        s3 = _rol32(((s3 ^ v1) + s1) & 0xFFFFFFFF, 17)
    t0 = s0 ^ length
    t1 = s1 ^ t0
    t2 = (s2 + t1) & 0xFFFFFFFF
    t3 = s3 ^ t2
    s0 = (_rol32(t0, 9) + _rol32(t2, 17)) & 0xFFFFFFFF
    s1 = _rol32(t1, 13) ^ _rol32(t3, 19)
    s2 = (_rol32(t2, 17) + s0) & 0xFFFFFFFF
    s3 = _rol32(t3, 19) ^ s1
    result = []
    for value in (s0, s1, s2, s3):
        result.extend(_le(value, 4))
    return result


def _xor_payload(payload: list[int]) -> bytearray:
    key = bytes.fromhex(HEX_KEY)
    return bytearray((value ^ key[i]) & 0xFF for i, value in enumerate(payload))


def compact_json(data: Optional[Union[dict[str, Any], str]]) -> str:
    # JS 侧签的是 JSON.stringify(body)，所以空格和非 ASCII 转义必须保持稳定。
    body = json.loads(data) if isinstance(data, str) else (data or {})
    return json.dumps(body, separators=(",", ":"), ensure_ascii=False)


def build_payload_array(
    http_data_md5: str,
    path_md5: str,
    a1_value: str,
    app_id: str = "xhs-pc-web",
    content_string: str = "",
    timestamp: Optional[float] = None,
    seed: Optional[int] = None,
    sign_state: Optional[SignState] = None,
) -> list[int]:
    if len(http_data_md5) != 32 or len(path_md5) != 32:
        raise ValueError("http_data_md5 and path_md5 must be 32-character hex strings")
    timestamp = time.time() if timestamp is None else timestamp
    seed = random.randint(0, 0xFFFFFFFF) if seed is None else seed & 0xFFFFFFFF
    seed_byte = seed & 0xFF
    # payload 是 144 字节的 mns0301 明文体，后续再异或和自定义 Base64。
    payload = list(VERSION_BYTES)
    payload.extend(_le(seed, 4))
    ts_bytes = _le(int(timestamp * 1000), 8)
    payload.extend(ts_bytes)
    if sign_state:
        payload.extend(_le(sign_state.page_load_timestamp, 8))
        payload.extend(_le(sign_state.sequence_value, 4))
        payload.extend(_le(sign_state.window_props_length, 4))
        payload.extend(_le(sign_state.uri_length, 4))
    else:
        # 这些浏览器生命周期值使用合理范围即可满足当前请求重放。
        offset = random.randint(10, 50)
        payload.extend(_le(int((timestamp - offset) * 1000), 8))
        payload.extend(_le(random.randint(15, 50), 4))
        payload.extend(_le(random.randint(1000, 1200), 4))
        payload.extend(_le(len(content_string.encode("utf-8")), 4))
    # 这里只取 x5 MD5 的前 8 字节，并逐字节混入 seed_byte。
    http_md5_bytes = bytes.fromhex(http_data_md5)
    payload.extend([http_md5_bytes[i] ^ seed_byte for i in range(8)])
    a1_bytes = a1_value.encode("utf-8")[:52].ljust(52, b"\x00")
    payload.append(len(a1_bytes))
    payload.extend(a1_bytes)
    app_bytes = app_id.encode("utf-8")[:10].ljust(10, b"\x00")
    payload.append(len(app_bytes))
    payload.extend(app_bytes)
    env = [1, seed_byte ^ ENV_TABLE[0]]
    env.extend(ENV_TABLE[i] ^ ENV_CHECKS_DEFAULT[i] for i in range(1, 15))
    payload.extend(env)
    path_md5_bytes = [int(path_md5[i : i + 2], 16) for i in range(0, 32, 2)]
    # 尾部校验绑定当前时间戳和 path 的 MD5。
    a3_hash = _custom_hash_v2(ts_bytes + path_md5_bytes)
    payload.extend(A3_PREFIX + [b ^ seed_byte for b in a3_hash])
    if len(payload) != PAYLOAD_LENGTH:
        raise AssertionError(f"payload length mismatch: {len(payload)}")
    return payload


def build_mns_x3(
    content_string: str,
    http_data_md5: str,
    path_md5: str,
    a1_value: str,
    app_id: str = "xhs-pc-web",
    timestamp: Optional[float] = None,
    seed: Optional[int] = None,
    sign_state: Optional[SignState] = None,
) -> str:
    payload = build_payload_array(http_data_md5, path_md5, a1_value, app_id, content_string, timestamp, seed, sign_state)
    return "mns0301_" + x3_b64_encode(_xor_payload(payload))


def decode_mns_x3(x3: str) -> bytearray:
    if x3.startswith("mns0301_"):
        x3 = x3[len("mns0301_") :]
    return _xor_payload(list(x3_b64_decode(x3)))


def standard_base64_decode(data: str) -> bytes:
    return base64.b64decode(data + "=" * ((4 - len(data) % 4) % 4))


def standard_base64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def build_enc_ssk_sign(
    md5_hex_value: str,
    ssk_map: dict[str, str],
    ea: int = 16,
    nonce_len: int = 16,
) -> Optional[dict[str, dict[str, str]]]:
    data_md5 = bytes.fromhex(md5_hex_value)
    if len(data_md5) != 16:
        return None
    enc_sign: dict[str, str] = {}
    enc_ssk: dict[str, str] = {}
    for key, value in ssk_map.items():
        if not key:
            continue
        try:
            decoded = standard_base64_decode(value)
        except Exception as exc:
            logger.debug("skip invalid ssk {}: {}", key, exc)
            continue
        if len(decoded) < ea:
            continue
        nonce = os.urandom(nonce_len)
        enc_value = nonce + hashlib.sha1(decoded + nonce).digest() + decoded[ea:]
        enc_sign[key] = standard_base64_encode(hashlib.sha1(data_md5 + enc_value).digest())
        enc_ssk[key] = standard_base64_encode(enc_value)
    if not enc_sign:
        return None
    return {"encSskSign": enc_sign, "encSsk": enc_ssk}


def sign_xs(
    uri: str,
    data: Optional[Union[dict[str, Any], str]],
    a1_value: str,
    app_id: str = "xhs-pc-web",
    platform: str = "Windows",
    sign_version: str = "4.4.3",
    timestamp: Optional[float] = None,
    seed: Optional[int] = None,
    sign_state: Optional[SignState] = None,
    ssk_map: Optional[dict[str, str]] = None,
) -> str:
    # 签名原文是 path + 紧凑 JSON body，不是完整 URL。
    body_json = compact_json(data)
    content_string = uri + body_json
    http_data_md5 = md5_hex(content_string)
    path_md5 = md5_hex(uri)
    x3 = build_mns_x3(content_string, http_data_md5, path_md5, a1_value, app_id, timestamp, seed, sign_state)
    sign_obj: dict[str, Any] = {
        "x0": sign_version,
        "x1": app_id,
        "x2": platform,
        "x3": x3,
        "x4": "object",
        "x5": http_data_md5,
    }
    if ssk_map:
        enc = build_enc_ssk_sign(http_data_md5, ssk_map)
        if enc:
            sign_obj["x6"] = enc["encSskSign"]
            sign_obj["x7"] = enc["encSsk"]
    xs = "XYS_" + custom_b64_encode(json.dumps(sign_obj, separators=(",", ":"), ensure_ascii=False))
    logger.debug("built x-s uri={} x5={} x3_len={}", uri, http_data_md5, len(x3))
    return xs


def decode_xs(xs: str) -> dict[str, Any]:
    if xs.startswith("XYS_"):
        xs = xs[4:]
    return json.loads(custom_b64_decode_to_str(xs))


def _encode_utf8_for_js(value: str) -> list[int]:
    escaped = quote(value, safe="")
    result = []
    i = 0
    while i < len(escaped):
        if escaped[i] == "%":
            result.append(int(escaped[i + 1 : i + 3], 16))
            i += 3
        else:
            result.append(ord(escaped[i]))
            i += 1
    return result


def _common_b64(data: list[int]) -> str:
    alphabet = CUSTOM_BASE64_ALPHABET
    out = []
    full_len = len(data) - (len(data) % 3)
    for i in range(0, full_len, 3):
        triplet = ((data[i] << 16) & 0xFF0000) + ((data[i + 1] << 8) & 0xFF00) + (data[i + 2] & 0xFF)
        out.append(alphabet[(triplet >> 18) & 63] + alphabet[(triplet >> 12) & 63] + alphabet[(triplet >> 6) & 63] + alphabet[triplet & 63])
    rem = len(data) % 3
    if rem == 1:
        value = data[-1]
        out.append(alphabet[value >> 2] + alphabet[(value << 4) & 63] + "==")
    elif rem == 2:
        value = (data[-2] << 8) + data[-1]
        out.append(alphabet[value >> 10] + alphabet[(value >> 4) & 63] + alphabet[(value << 2) & 63] + "=")
    return "".join(out)


def _crc32_variant(value: Union[str, list[int]]) -> int:
    table = []
    for n in range(256):
        c = n
        for _ in range(8):
            c = (c >> 1) ^ 0xEDB88320 if c & 1 else c >> 1
        table.append(c & 0xFFFFFFFF)
    c = -1
    iterable = (ord(ch) for ch in value) if isinstance(value, str) else iter(value)
    for item in iterable:
        c = table[(c & 255) ^ item] ^ (c >> 8)
    return (-1 ^ c ^ 0xEDB88320) & 0xFFFFFFFF


def _platform_code(platform: str) -> int:
    return {"Android": 1, "iOS": 2, "Mac OS": 3, "Linux": 4}.get(platform, 5)


def _x12(timestamp_ms: Optional[int] = None) -> str:
    global _FIRST_VISIT_MS
    now_ms = int(time.time() * 1000) if timestamp_ms is None else timestamp_ms
    if _FIRST_VISIT_MS is None:
        _FIRST_VISIT_MS = now_ms
    return f"{now_ms};{_FIRST_VISIT_MS}"


def build_x_s_common(
    platform: str = "Windows",
    app_id: str = "xhs-pc-web",
    web_build: str = "6.53.1",
    timestamp_ms: Optional[int] = None,
) -> str:
    # x-s-common 是紧凑 JSON，再用外层同一套自定义字符表编码。
    obj = {
        "s0": _platform_code(platform),
        "s1": "",
        "x0": 1,
        "x1": "4.4.3",
        "x2": platform,
        "x3": app_id,
        "x4": web_build,
        "x5": "i",
        "x6": "",
        "x7": "",
        "x8": X_S_COMMON_SEED,
        "x9": _crc32_variant(X_S_COMMON_SEED),
        "x10": 0,
        "x11": "normal",
        "x12": _x12(timestamp_ms),
    }
    raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    result = _common_b64(_encode_utf8_for_js(raw))
    logger.debug("built x-s-common len={} x9={}", len(result), obj["x9"])
    return result


def build_signed_headers(
    url: str,
    body: Optional[Union[dict[str, Any], str]],
    cookies: dict[str, str],
    headers: Optional[dict[str, str]] = None,
    refresh_common: bool = False,
) -> dict[str, str]:
    final_headers = dict(DEFAULT_HEADERS if headers is None else headers)
    timestamp_ms = int(time.time() * 1000)
    uri = urlparse(url).path
    final_headers["x-t"] = str(timestamp_ms)
    final_headers["x-s"] = sign_xs(uri, body, cookies["a1"], timestamp=timestamp_ms / 1000)
    if refresh_common or not final_headers.get("x-s-common"):
        final_headers["x-s-common"] = build_x_s_common(timestamp_ms=timestamp_ms)
    return final_headers


def validate_signature(url: str = DEFAULT_URL, body: str = DEFAULT_BODY, cookies: Optional[dict[str, str]] = None) -> bool:
    cookies = DEFAULT_COOKIES if cookies is None else cookies
    headers = build_signed_headers(url, body, cookies, refresh_common=True)
    uri = urlparse(url).path
    obj = decode_xs(headers["x-s"])
    payload = decode_mns_x3(obj["x3"])
    expected_x5 = md5_hex(uri + compact_json(body))
    checks = {
        "prefix": headers["x-s"].startswith("XYS_"),
        "x5": obj["x5"] == expected_x5,
        "x3_prefix": obj["x3"].startswith("mns0301_"),
        "x3_len": len(obj["x3"]) == 200,
        "payload_len": len(payload) == PAYLOAD_LENGTH,
        "version": list(payload[:4]) == VERSION_BYTES,
        "x4": obj["x4"] == "object",
    }
    for name, ok in checks.items():
        logger.info("check {}={}", name, ok)
    return all(checks.values())


def post_homefeed(refresh_common: bool = False, timeout: int = 20) -> requests.Response:
    headers = dict(DEFAULT_HEADERS)
    # demo 优先使用抓包 common；抓包 common 置空或 refresh_common=True 时动态生成。
    if CAPTURED_X_S_COMMON and not refresh_common:
        headers["x-s-common"] = CAPTURED_X_S_COMMON
    signed_headers = build_signed_headers(DEFAULT_URL, DEFAULT_BODY, DEFAULT_COOKIES, headers=headers, refresh_common=refresh_common)
    logger.info("POST {}", DEFAULT_URL)
    logger.info("x-t={} x-s-prefix={} x-common-len={}", signed_headers["x-t"], signed_headers["x-s"][:12], len(signed_headers["x-s-common"]))
    response = requests.post(DEFAULT_URL, headers=signed_headers, cookies=DEFAULT_COOKIES, data=DEFAULT_BODY, timeout=timeout)
    logger.info("status={} bytes={}", response.status_code, len(response.content))
    try:
        payload = response.json()
        logger.info("api success={} code={} msg={}", payload.get("success"), payload.get("code"), payload.get("msg"))
    except ValueError:
        logger.warning("response is not json")
    return response


def main() -> None:
    setup_logger()
    ok = validate_signature()
    if not ok:
        raise SystemExit("local signature validation failed")
    response = post_homefeed(refresh_common=False)
    print(response.status_code, flush=True)
    sys.stdout.buffer.write(response.text.encode("utf-8", errors="replace"))
    sys.stdout.buffer.write(b"\n")


if __name__ == "__main__":
    main()
