# -*- coding: utf-8 -*-
"""
京东首页 feed 多页抓取（纯 Python，无需浏览器）

用法:
  python jd_feed_pages.py                # 默认抓 5 页
  python jd_feed_pages.py -n 20          # 抓 20 页
  python jd_feed_pages.py -n 20 -d 4     # 抓 20 页，每页间隔 4 秒
  python jd_feed_pages.py -n 10 -o out.json

说明:
  - 每页都重新走 request_algo 换取新的 token/rd（签名必须配套）
  - 命中 403(风控) / 605(设备验证) 时自动换一套 __jd cookie 重试
  - 同一页最多重试 3 次；连续失败则停止
  - 结果按 sku/wareId 去重后写入 JSON
"""
import argparse
import io
import json
import random
import sys
import time

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
from loguru import logger
import h5st
from jd_session import JDSession

FUNCTION_ID = "pc_home_feed"
APP_ID = "b5216"


def build_body(page: int, pagesize: int, area: str = "") -> str:
    return json.dumps({"page": page, "pagesize": pagesize, "area": area,
                       "source": "pc-home", "kuangjia": 1, "notJsonp": True},
                      ensure_ascii=False, separators=(',', ':'))


def fetch_page(s: JDSession, page: int, pagesize: int = 25, area: str = ""):
    """抓取单页，返回 (items, code, msg, http)"""
    fp = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(16))
    token, rd = s.get_token_rd(fp, app_id=APP_ID)
    body = build_body(page, pagesize, area)
    r = h5st.sign(FUNCTION_ID, body, token, fp=fp, rd=rd)
    params = {"appid": "www-jd-com", "client": "pc", "clientVersion": "1.0.0",
              "t": r["t"], "uuid": s.uuid, "body": body,
              "functionId": FUNCTION_ID, "h5st": r["h5st"], "loginType": "3"}
    resp = s.get("https://api.m.jd.com/", headers=s.api_headers(), params=params, timeout=20)
    if not resp.text.strip():
        return None, None, "empty", resp.status_code
    j = resp.json()
    code = j.get("code")
    if code == 0:
        return j["data"]["data"], code, j.get("msg"), resp.status_code
    return None, code, j.get("msg"), resp.status_code


def item_key(it: dict) -> str:
    for k in ("sku", "spu", "wareId", "sku_id", "id"):
        if it.get(k):
            return str(it[k])
    return json.dumps(it, sort_keys=True, ensure_ascii=False)[:120]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", "--pages", type=int, default=5, help="抓取页数")
    ap.add_argument("-p", "--page-size", type=int, default=25, help="每页条数")
    ap.add_argument("-d", "--delay", type=float, default=4.0, help="页间间隔秒数")
    ap.add_argument("-a", "--area", default="", help="地区参数(空=默认)")
    ap.add_argument("-o", "--out", default="feed_pages.json", help="输出文件")
    ap.add_argument("--start", type=int, default=1, help="起始页码")
    args = ap.parse_args()

    s = JDSession()
    all_items, seen = [], set()
    consecutive_fail = 0

    for page in range(args.start, args.start + args.pages):
        items = None
        for attempt in range(1, 4):
            try:
                items, code, msg, http = fetch_page(s, page, args.page_size, args.area)
            except Exception as e:
                logger.warning(f"p{page} 第{attempt}次异常: {e}")
                items, code, msg, http = None, None, str(e), 0
            if items:
                break
            # 风控/设备验证 -> 换 cookie 重试
            if code in (None, "605") or http in (403, 0):
                logger.warning(f"p{page} 第{attempt}次失败 (HTTP {http} code={code})，更换会话重试")
                s = JDSession()
                time.sleep(3 + attempt * 2)
            else:
                logger.warning(f"p{page} 业务异常 code={code} msg={msg}")
                break

        if not items:
            consecutive_fail += 1
            logger.error(f"p{page} 放弃 (code={code} msg={msg})")
            if consecutive_fail >= 2:
                logger.error("连续 2 页失败，停止抓取")
                break
            time.sleep(args.delay)
            continue

        consecutive_fail = 0
        new = 0
        for it in items:
            k = item_key(it)
            if k not in seen:
                seen.add(k)
                all_items.append(it)
                new += 1
        logger.success(f"p{page} 获取 {len(items)} 条 (新增 {new}) 累计 {len(all_items)}")

        if not items:
            logger.info(f"p{page} 返回空列表，已到末页")
            break
        # 本页数据全为重复 => 到底了
        if new == 0 and page > args.start:
            logger.info("本页无新数据，视为已到末页，停止")
            break

        time.sleep(args.delay)

    json.dump(all_items, open(args.out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    logger.success(f"共 {len(all_items)} 条，已写入 {args.out}")


if __name__ == "__main__":
    main()
