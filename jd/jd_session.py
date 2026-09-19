# -*- coding: utf-8 -*-
"""
京东纯 Python 会话材料（无需浏览器、无需 eid）

结论（实测验证）:
  - feed 接口必需的 cookie 只有 __jd 家族 5 个: __jda __jdb __jdc __jdu __jdv
    它们是访问统计 cookie（非设备指纹），格式简单，可完全自行构造。
  - x-api-eid-token 参数与 3AB9D23F*/jcap/sdtoken 等设备指纹 cookie **均非必需**，
    去掉后请求依然 code=0（各测 3 轮）。故 jcap SDK 无需逆向。
  - 缺 cookie 或 cookie 无效时返回 605（滑块验证）。

cookie 结构（对照真实值反推）:
  __jdc = clientId，固定 76161171
  __jdu = 毫秒时间戳(13位) + 9 位随机数字
  __jda = "{cid}.{uid}.{t0}.{t0}.{t0}.1"     t0 = 秒级时间戳
  __jdb = "{cid}.1.{uid}|1.{t0}"
  __jdv = "{cid}|direct|-|none|-|{ms}"
"""
import random
import time

from curl_cffi import requests
from loguru import logger

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36")
DEFAULT_CID = "76161171"


def gen_cookies(cid: str = DEFAULT_CID, ms: int = None) -> dict:
    """生成一套可用的 __jd 家族 cookie"""
    ms = ms or int(time.time() * 1000)
    uid = str(ms) + ''.join(random.choice('0123456789') for _ in range(9))
    t0 = ms // 1000
    ck = {
        "__jdc": cid,
        "__jdu": uid,
        "__jda": f"{cid}.{uid}.{t0}.{t0}.{t0}.1",
        "__jdb": f"{cid}.1.{uid}|1.{t0}",
        "__jdv": f"{cid}|direct|-|none|-|{ms}",
    }
    logger.debug(f"生成 __jd cookies: {ck}")
    return ck


class JDSession:
    """纯 Python 京东会话：自带可自造 cookie，封装 token/rd 获取与请求头"""

    def __init__(self, cid: str = DEFAULT_CID, cookies: dict = None):
        self.s = requests.Session(impersonate="chrome")
        self.cookies = cookies if cookies is not None else gen_cookies(cid)
        self.s.cookies.update(self.cookies)
        self.uuid = self.cookies["__jda"]
        logger.info(f"JDSession 就绪: {len(self.cookies)} 个 cookie")

    def get_token_rd(self, fp: str, app_id: str = "b5216"):
        import h5st
        return h5st.get_token_rd(self.s, fp, app_id)

    def api_headers(self, referer: str = "https://www.jd.com/") -> dict:
        return {
            "accept": "application/json, text/plain, */*",
            "accept-language": "zh,zh-CN;q=0.9",
            "origin": "https://www.jd.com",
            "referer": referer,
            "user-agent": UA,
            "x-referer-page": referer,
            "x-rp-client": "h5_2.2.0",
        }

    def post(self, url, **kw):
        return self.s.post(url, **kw)

    def get(self, url, **kw):
        return self.s.get(url, **kw)
