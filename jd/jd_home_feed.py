# -*- coding: utf-8 -*-
"""
京东 api.m.jd.com 请求示例（functionId=pc_home_feed）—— 全流程纯 Python，无浏览器/JS

  1. JDSession()    : 自行生成 __jd 家族 cookie（无需浏览器，无需 eid）
  2. get_token_rd() : POST cactus.jd.com/request_algo 取服务端 token/rd
  3. h5st.sign()    : 纯 Python 计算 10 字段 h5st
  4. GET api.m.jd.com -> {"code":0,"msg":"Success"}

用法: python jd_home_feed.py
依赖: curl_cffi, loguru, h5st.py, jd_session.py
"""
import io
import json
import random
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
from loguru import logger
import h5st
from jd_session import JDSession


def main():
    s = JDSession()

    # ---- 1. 换取服务端 token / rd ----
    fp = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(16))
    token, rd = s.get_token_rd(fp, app_id="b5216")

    # ---- 2. 纯 Python h5st 签名 ----
    body = '{"page":1,"pagesize":25,"area":"","source":"pc-home","kuangjia":1,"notJsonp":true}'
    r = h5st.sign("pc_home_feed", body, token, fp=fp, rd=rd)
    params = {
        "appid": "www-jd-com", "client": "pc", "clientVersion": "1.0.0",
        "t": r["t"], "uuid": s.uuid, "body": body, "functionId": "pc_home_feed",
        "h5st": r["h5st"], "loginType": "3",
    }

    # ---- 3. 请求 ----
    resp = s.get("https://api.m.jd.com/", headers=s.api_headers(), params=params, timeout=20)
    logger.info(f"HTTP {resp.status_code} len={len(resp.text)}")
    if not resp.text.strip():
        logger.error(f"空响应 HTTP {resp.status_code}：会话被风控标记（请求过频），"
                     f"稍后重试或更换 clientId")
        sys.exit(2)
    j = resp.json()
    logger.info(f"code={j.get('code')} msg={j.get('msg')}")
    if j.get("code") == 0:
        feed = j["data"]["data"]
        logger.success(f"feed items: {len(feed)}")
        print(json.dumps(feed[0], ensure_ascii=False)[:300])
    elif j.get("code") == "605":
        logger.warning("605 设备验证：cookie 被判无效，稍后重试")
        sys.exit(3)
    else:
        logger.warning(f"异常响应: {resp.text[:200]}")
        sys.exit(4)


if __name__ == "__main__":
    main()
