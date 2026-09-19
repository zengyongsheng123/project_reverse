# 京东 h5st 5.3 逆向（纯 Python，无浏览器）

京东 `api.m.jd.com` 的 `h5st` 5.3 签名纯 Python 实现。已完整逆向并经端到端验证：
`GET api.m.jd.com` 返回 `{"code":0,"msg":"Success"}` 与真实商品流数据（~220KB）。

完整算法分析见 [docs/h5st_5.3_算法分析.md](docs/h5st_5.3_算法分析.md)。

## 结论：全套链路不需要浏览器

| 项 | 结论 |
|---|---|
| `h5st` 10 字段签名 | 纯 Python 计算 |
| `token` / `rd` | 由 `cactus.jd.com/request_algo` 服务端下发（**不能自造**） |
| `__jd` 家族 cookie | 访问统计 cookie，**可自行构造** |
| `x-api-eid-token`（eid） | **不必需**，jcap SDK 无需逆向 |
| 浏览器 / JS 运行时 | **完全不需要** |

## 快速开始

```bash
pip install curl_cffi loguru
python jd_home_feed.py                    # 单页
python jd_feed_pages.py -n 20 -d 6        # 多页（-n 页数 / -d 页间秒数）
```

## 代码用法

```python
import random
import h5st
from jd_session import JDSession

s = JDSession()                                     # 自造 __jd cookie
fp = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(16))
token, rd = s.get_token_rd(fp, app_id="b5216")      # 服务端下发 token/rd

r = h5st.sign("pc_home_feed", body, token, fp=fp, rd=rd)
params = {"appid": "www-jd-com", "client": "pc", "clientVersion": "1.0.0",
          "t": r["t"], "uuid": s.uuid, "body": body,
          "functionId": "pc_home_feed", "h5st": r["h5st"], "loginType": "3"}
resp = s.get("https://api.m.jd.com/", headers=s.api_headers(), params=params)
```

## h5st 结构

```
ts17;fp;appId;token;signStr(f5);5.3;t;envB64(f8);signedStr(f9);stkB64(f10)
```

核心算法：

```
keystr = token + fp + ts17 + "52" + appId + salt + "=@3k4k"
salt   = rd(12) + 9个ALPHA2校验字符(对 keystr 原料分9块求和)
keyhex = swap7(sha256(keystr))              # swap7: 前7字节反转
iKey   = SBOX(reverse(keyhex[:16]))^0x36 ‖ keyhex[16:]^0x36
oKey   = iKey ^ 0x6a
f5/f9  = swap7(sha256(oKey ‖ sha256(iKey ‖ msg)))   # 自定义 MAC
f8/f10 = 自定义 base64（自定义字母表 + 短尾组特殊补齐 + 整体反转）
ts17   = format(t + 3000ms)，东八区
```

## 三条铁律

1. **`rd` 不能自造** —— 必须由 `request_algo` 下发，服务端用它重建签名密钥；自造 → HTTP 403。
2. **必须有 `__jd` 家族 cookie**（`__jda/__jdb/__jdc/__jdu/__jdv`），缺失 → 605 滑块。
3. **`fp` 全程唯一** —— 换 token 时用的 fp 必须与最终签名的 fp 相同。

## 文件说明

| 文件 | 说明 |
|---|---|
| `h5st.py` | h5st 5.3 签名核心（含 loguru 日志与自测） |
| `jd_session.py` | 纯 Python 会话材料（自造 `__jd` cookie，无需浏览器） |
| `jd_home_feed.py` | 单页请求示例 |
| `jd_feed_pages.py` | 多页抓取（限速 + 自动换会话重试 + 去重） |
| `trace_collect.py` | JSVMP 插桩采集工具（Playwright） |
| `tools/` | 插桩与混淆字符串解码脚本 |
| `js/` | 京东原始 / 插桩后的 JS（逆向素材） |
| `recon/` | 插桩 trace 与抓包中间产物 |
| `docs/` | 算法分析报告 |

## 逆向方法

1. 对 JSVMP（`js_security_v3_0.1.4.js`）做 blanket 日志插桩：
   `tools/blanket_log.js` 向 37 个分发循环的 1666 个 case 注入 `__vlog`，
   配合 `trace_collect.py` 捕获完整执行 trace（`recon/vm_trace.txt`）。
2. 由 trace 定位 `keystr` 构造点（检索 `=@3k4k`），逐个还原 salt / iKey / MAC 等步骤。
3. 对每个待定参数做"服务端校验强度探测"（重放 / 置空 / 篡改），快速排除非必需参数
   （`expandParams`、`x-api-eid-token` 均由此判定为可省）。

## 注意

仅供学习与研究使用。请遵守目标网站的服务条款，控制请求频率（实测页间 ≥6 秒可稳定连续抓取 20 页）。
