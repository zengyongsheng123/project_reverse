---
name: jd-h5st-sign
description: 生成京东 api.m.jd.com 请求的 h5st 5.3 签名（纯 Python、无浏览器），或排查京东签名/风控相关失败。当任务涉及请求 jd.com / api.m.jd.com 接口、h5st 参数、京东反爬、pc_home_feed 等接口时使用。
---

# 京东 h5st 5.3 纯 Python 签名（全流程无浏览器）

项目目录 `d:\jd_20260919`。算法已完整逆向，端到端验证通过（HTTP 200 `code:0 Success`）。
完整算法细节见 [docs/h5st_5.3_算法分析.md](docs/h5st_5.3_算法分析.md)。

**整套链路不需要浏览器、不需要 JS 运行时、不需要 eid。** 直接跑：

```bash
python jd_home_feed.py                    # 单页
python jd_feed_pages.py -n 20 -d 6        # 多页（-n 页数, -d 页间秒数）
```

## 代码用法

```python
import random
import h5st
from jd_session import JDSession

s = JDSession()                                    # 自造 __jd cookie，无浏览器
fp = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(16))
token, rd = s.get_token_rd(fp, app_id="b5216")     # token/rd 必须服务端下发

r = h5st.sign("pc_home_feed", body, token, fp=fp, rd=rd)
params = {"appid": "www-jd-com", "client": "pc", "clientVersion": "1.0.0",
          "t": r["t"], "uuid": s.uuid, "body": body,
          "functionId": "pc_home_feed", "h5st": r["h5st"], "loginType": "3"}
resp = s.get("https://api.m.jd.com/", headers=s.api_headers(), params=params)
```

## 三条铁律（违反必失败）

1. **rd 不能自造**。必须 `get_token_rd()` 从 `cactus.jd.com/request_algo` 获取
   （藏在返回 `algo` 字符串的 `var rd='...'` 里）。自造 rd → HTTP 403 空响应。
2. **必须有 `__jd` 家族 cookie**（`__jda/__jdb/__jdc/__jdu/__jdv`）。缺失 → 605 滑块。
   这 5 个可自造，`jd_session.gen_cookies()` 已实现。
3. **fp 全程唯一**：换 token 时用的 fp 必须与最终签名的 fp 是同一个。

## 不需要的东西（已验证，别再花时间逆向）

| 项 | 结论 |
|---|---|
| `x-api-eid-token`（eid） | **不必需**。加不加都 code=0；其签发接口 `jra.jd.com/jsTk.do` 严格校验 9.9KB 指纹 blob，但可直接绕过 |
| `3AB9D23F7A4B3C9B/SS` | 不必需（eid 类 cookie） |
| `shshshfpa/fpb/fpx`、`sdtoken`、`jcap_dvzw_fp` | 不必需 |
| jcap SDK（`pc-tk.js`） | 不必需，无需逆向 |
| `expandParams`（request_algo 参数） | 服务端不校验，可省略 |

## 排错对照

| 现象 | 原因 | 处理 |
|---|---|---|
| HTTP 403 空响应 | ① rd 自造/token 过期/签名错；② **会话触发频率风控** | 换一套 cookie（新建 `JDSession`）或加大页间间隔（≥6s）；仍失败跑 `python h5st.py` 自测签名 |
| HTTP 200 `code:"605"` | `__jd` cookie 缺失或无效 | 重建 `JDSession()` |
| 响应非 JSON / 空 | 同 403，风控 | 同上 |
| `algo.SHA256 is not a function`（插桩时） | 误擦 `_algos`（CryptoJS 算法注册表） | 恢复该对象，它不是盐缓存 |
| ts17 被拒 | 忘了 +3000ms 偏移 | `h5st.py` 的 `_ts17(ms+3000)` 已内置 |
| 中文日志乱码 | Windows 控制台 GBK | loguru stderr 已 reconfigure utf-8 |

## 换接口 / 换 appId

- 其他 functionId：只改 `h5st.sign(function_id, body, ...)` 的入参，算法不变。
- 其他 appId（h5st 字段3）：`get_token_rd(fp, app_id="...")` 与 `sign(..., app_id="...")` 传同一个值。
- `body` 参与签名的是其 **sha256hex**，不是原文（h5st.py 已处理）。

## 重新逆向 / JD 改版时

1. `python trace_collect.py` — Playwright + blanket 插桩采集 VM trace
   （工具链：`tools/blanket_log.js`、`js/js_security_v3_0.1.4.instrumented.js`）
2. 在 `recon/vm_trace.txt` 检索 `=@3k4k` 定位 keystr 构造点，逐步骤比对中间值。
3. 插桩期间不要 wipe `_algos`、不要 patch `signSync`（均有反制）。
