# 京东 h5st 5.3 算法分析报告

> 目标站点：`https://www.jd.com/` → `https://api.m.jd.com/`（示例接口 `functionId=pc_home_feed`）
> 签名文件：`js_security_v3_0.1.4.js`（window.ParamsSign，JSVMP 虚拟机保护）
> 验证方式：对 JSVMP 分发循环做 blanket 日志插桩（1666 处 case 注入 `__vlog`），
> 捕获完整执行 trace（`recon/vm_trace.txt`，59223 行），逐字段比对真值。
> 交付物：`h5st.py`（纯 Python 实现，自测与 trace 真值字节级一致），
> 端到端请求实测返回 `{"code":0,"msg":"Success"}`。

---

## 1. 总览

h5st 是请求 URL 中 `h5st` 参数的值，10 个分号分隔字段：

```
ts17;fp;appId;token;signStr;5.3;t;envB64;signedStr;stkB64
 f1   f2   f3    f4    f5   f6  f7   f8      f9      f10
```

| 字段 | 名称 | 内容 | 来源 |
|---|---|---|---|
| f1 | ts17 | `yyyyMMddHHmmssSSS`（东八区 17 位） | `format(t + 3000ms)` |
| f2 | fp | 16 位 `[a-z0-9]` 随机设备指纹 | 客户端生成 |
| f3 | appId | 签名 appId，pc 首页为 `b5216` | 固定 |
| f4 | token | `tk03` 开头 92 字符会话 token | **request_algo 服务端下发** |
| f5 | signStr | 64 位 hex，请求参数签名 | 自定义 MAC（本文 §4） |
| f6 | ver | 固定 `5.3` | 固定 |
| f7 | t | 13 位毫秒时间戳（签名时刻） | 客户端生成 |
| f8 | envB64 | 环境指纹 JSON 的自定义 base64 | §6 |
| f9 | signedStr | 64 位 hex，常量消息签名 | 自定义 MAC（本文 §5） |
| f10 | stkB64 | 参与签名字段名的自定义 base64 | §6 |

**线上请求的三条硬约束**（都是踩坑后的结论）：

1. **f4 token 与 salt 中的 rd 必须由 `POST https://cactus.jd.com/request_algo` 下发**。
   服务端保存了自己签发的 rd，验签时用它重建密钥；客户端自造 rd 会得到 HTTP 403（空响应）。
   响应 JSON：`data.result.tk`（token）、`data.result.algo`（函数字符串，内含 `var rd='xxxxxxxxxxxx'`）。
   请求体 `expandParams` 服务端不校验，可省略。
2. **需要 `__jd` 家族 cookie**（`__jda/__jdb/__jdc/__jdu/__jdv`），缺失或无效返回 605 滑块挑战。
   这 5 个是访问统计 cookie，**可纯 Python 自行构造**（见 §11），无需浏览器。
3. f7 `t` 与 f1 `ts17` 关系恒为 `ts17 = t + 3000ms`（8 组样本偏移恰为 3000）。

---

## 2. 密钥派生

### 2.1 keystr（密钥原材料）

```
keystr = token + fp + ts17 + "52" + appId + salt + "=@3k4k"
```

trace 实证（recon/vm_trace.txt 第 34519-34523 行，VM 内 `concat` 链 + `parse` 调用）。

### 2.2 salt（21 字符）

```
salt   = rd(12字符) + tail(9字符)
s      = token + fp + ts17 + "52" + appId + rd
blk    = len(s) // 9          # 92+16+17+2+5+12 = 144 → blk = 16
tail[j] = ALPHA2[(3 * Σ ord(c)) % 64]   c ∈ s[blk*j : blk*(j+1)], j = 0..8
```

`ALPHA2`（64 字符自定义字母表）：

```
nmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA-_9876543210zyxwvutsrqpo
```

### 2.3 keyhex / iKey / oKey

```
keyhex = swap7(sha256(keystr).digest()).hex()
swap7(d) = d[6::-1] + d[7:]            # 前 7 字节反转，其余不变

iKey = SBOX(keyhex[:16] 反转) ^ 0x36  ‖  keyhex[16:] ^ 0x36   # 按字节
oKey = iKey ^ 0x6a                                            # 按字节
```

`SBOX`（十六进制字符 → 符号的替换表）：

```
0→e  1→l  2→s  3→z  4→"  5→)  6→0  7→7  8→>  9→E  a→@  b→G  c→N  d→U  e→\  f→c
```

### 2.4 自定义 MAC（f5 / f9 共用）

```
f5/f9 = swap7(sha256( oKey ‖ sha256( iKey ‖ msg ).digest() ).digest()).hex()
```

即 HMAC-SHA256 结构，但用派生的 iKey/oKey 手搓（标准 ipad=0x36 / opad=0x5c 被换成 0x36/0x6a，
且前后各套一层 swap7）。

---

## 3. _seData1（se1）变换

对消息 `m` 追加 9 个校验字符（用于构造 msg5/msg9）：

```
L = len(m);  g = L // 9
out = m + join(ALPHA2[(3 * Σ ord(c)) % 64]  for c in m[j*g:(j+1)*g], j=0..7)
          + ALPHA2[(3 * Σ ord(c)) % 64]  for c in m[8*g:]        # 最后一块取剩余全部
```

注意最后一块是 `m[8g:]`（到结尾），不是 `m[8g:9g]`。

---

## 4. f5（signStr）—— 请求参数签名

**参与签名的参数对**（f10 `_stk` 解码可验证字段集合）：

```
appid, body, client, clientVersion, functionId, t
```

- `body` 的值不是原文，而是 `sha256hex(请求体)`。
- 参数对按 key 字典序排列。

**构造消息**：

```
paramsStr = "appid:www-jd-com&body:<sha256hex>&client:pc&clientVersion:1.0.0&functionId:pc_home_feed&t:<ms>"
msg5      = se1(se1(paramsStr)[:-2]) + "=@3k4k"        # 注意是前导 '='，去掉上一轮追加的末 2 字符
f5        = 自定义MAC(iKey, oKey, msg5)
```

## 5. f9（signedStr）—— 常量消息签名

```
msg9 = se1(se1("appid:appid&functionId:functionid")[:-2]) + "=@3k4k"
f9   = 自定义MAC(iKey, oKey, msg9)
```

消息为**字面字符串**（"appid"/"functionid" 不是变量代入），因此 f9 只随密钥变化，
在同一 token 会话内是常量。trace 已逐字节验证。

---

## 6. 自定义 Base64（f8 / f10）

字母表 `B64MAP`（注意是标准 base64 字母表的**逆序**变体）：

```
rqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA-_9876543210zyxwvuts
```

编码规则：

- 每 3 字节 → 4 字符（大端 bit 切分，同标准 base64）；
- 尾部不满 3 字节时：**第 4 字符不用 padding，而是 `B64MAP[缺失字节数]`**
  （缺 1 字节 → `B64MAP[1]`，缺 2 字节 → `B64MAP[2]`），前 3 字符正常编码；
- 全部编码完成后，**整个字符串反转**。

解码：先反转，再按 4 字符组查表（`B64MAP` 逆映射），每组 24 bit → 3 字节。

### f8 明文结构（env JSON，596 字节 → 796 字符）

```json
{
  "sua": "Windows NT 10.0; Win64; x64",
  "pp": {},
  "extend": { "wd":0, "l":0, "ls":5, "wk":64, "bu1":"0.1.4", "bu3":43, "bu4":0,
              "bu5":0, "bu6":29, "bu7":0, "bu8":0, "random":"<10字符>",
              "bu12":-8, "bu10":14, "bu11":4, "bu13":"Aj,F1,Al" },
  "pf": "Win32",
  "random": "<11字符>",
  "v": "h5_file_v5.3.5",
  "bu4": "0",
  "canvas": "<32位md5>",
  "webglFp": "<32位md5>",
  "ccn": 16,
  "bu14": "<10字符>",
  "t": <签名时刻ms>,
  "fp": "<与 h5st 字段2一致>"
}
```

关键约束：`env.fp` 必须等于 h5st 字段 2 的 fp；`env.t` 为签名时刻毫秒值。
其余 random/canvas/webglFp 服务端不做一致性校验（实测可随机）。

### f10 明文

参与签名字段名的逗号连接：`"appid,body,client,clientVersion,functionId,t"`（44 字节 → 60 字符）。

---

## 7. token / rd 的获取（request_algo）

```
POST https://cactus.jd.com/request_algo
Content-Type: application/json

{ "version": "5.3", "fp": "<16字符>", "appId": "b5216",
  "timestamp": <ms>, "platform": "web" }
```

响应：

```json
{ "status": 200, "data": { "result": {
    "tk": "tk03...",
    "fp": "...",
    "algo": "function test(tk,fp,ts,ai,algo){var rd='M1NCoIwPvIjK';...}"
}}}
```

- `tk` 即 h5st 字段 4 token；从 `algo` 字符串中正则提取 `rd='(.{12})'`。
- 每个 appId 独立签发一套 (token, rd)；pc 首页 feed 用 `b5216`。
- fp 需在请求 algo 与最终签名时保持同一个值（服务端绑定 token↔fp）。

**为什么不能自造 rd**：客户端 keystr 含 salt、salt 含 rd，而 rd 不出现在任何上行参数中；
服务端只能用自己签发时保存的 rd 重建 salt → 重建 keyhex → 验算 f5/f9。
自造 rd 时 f5/f9 与服务端期望不符，边缘网关直接 403 空响应。

---

## 8. JSVMP 插桩方法（复现/升级时用）

1. `trace_collect.py` 用 Playwright `page.route` 拦截 js_security_v3 请求，
   以 `js/js_security_v3_0.1.4.instrumented.js` fulfill（blanket 插桩版）。
2. `tools/blanket_log.js` 对 37 个 VM 分发循环的全部 1666 个 case 注入
   `if(!window.__quiet)__vlog(pc-1,N,"");`，`__vlog` 记录 pc/操作码/操作数快照
   （`window.__s` 序列化，含 CryptoJS WordArray 的 words+sigBytes）。
3. genKey 循环（文件偏移 136488，codevar `w`，pcvar `u`，51 个 case）操作码语义已解码：
   53=压常量、32=调 d3、47=取属性、60=调 d4、43=加、27=减、65=乘、57=除、
   37=.length、33=<、90/94=条件跳、88=返回弹栈。
4. 还原关键调用链（trace 行号）：genKey 源串构造 4385-4406（`XyxoB` 实为 `||` 辅助函数），
   keystr concat 34519，`_stk`/`env` 构造在同 trace 内可检索。

---

## 9. 验证记录

| 项目 | 方法 | 结果 |
|---|---|---|
| salt 公式 | 冻结 trace 时间戳自测 | ✅ `a9B0qDgOvNcZmROhryZgV` 一致 |
| f9 | 同上 | ✅ 逐字节一致 |
| f10 | 同上 | ✅ 逐字节一致 |
| f5 | h5log2 精确 cfg（body hash + t + trace keystr） | ✅ 一致 |
| f8 | 解码浏览器值 vs Python 值结构比对 | ✅ 结构一致（596B→796字符） |
| 端到端 | `jd_home_feed.py` 纯 Python 请求 | ✅ HTTP 200 `code:0 Success`，~220KB 真实数据（多轮复验） |

## 10. 文件清单

| 文件 | 说明 |
|---|---|
| `h5st.py` | 纯 Python h5st 5.3 实现（含 loguru 日志、自测） |
| `jd_session.py` | 纯 Python 会话材料（自造 `__jd` cookie，无浏览器） |
| `jd_home_feed.py` | 完整请求示例（全流程纯 Python） |
| `trace_collect.py` / `tools/blanket_log.js` / `js/*.instrumented.js` | JSVMP 插桩采集工具链 |
| `recon/vm_trace.txt` 等 | 插桩证据与中间数据 |

---

## 11. eid 结论：不必需（原计划逆向，实测规避）

京东的 `x-api-eid-token`（eid）由 jcap SDK（`gias.jd.com/js/pc-tk.js`）生成，
签发接口为 `POST https://jra.jd.com/jsTk.do`，参数 `a=<约 9.9KB 混淆设备指纹 blob>`，
响应 `data.token`（= `jdd03` + `data.eid` + 33 字符后缀）。

**实测结论：feed 接口不需要 eid**，该 blob 服务端严格校验（逐字重放亦返回 `code=20`），
但可以直接绕过——不需要它。

### 必需 cookie 最小集测试

| cookie 组合 | 结果 |
|---|---|
| `__jda __jdb __jdc __jdu __jdv` | ✅ code=0 |
| `__jda __jdb __jdc __jdu __jdv` + shshshfpa/b/x | ✅ code=0 |
| 仅 `shshshfpa/b/x` | ❌ 605 |
| 仅 `3AB9D23F7A4B3C9B/SS`（eid 类） | ❌ 605 |
| 无任何 cookie | ❌ 605 |
| 含 `x-api-eid-token` 参数但无 `__jd` 家族 | ❌ 605 |

→ **唯一必需的是 `__jd` 家族 5 个 cookie**；eid 参数、eid cookie、shshsh、jcap 全部可省。

### `__jd` 家族格式（可自造）

```
__jdc = clientId，固定 76161171
__jdu = "{ms}{9位随机数字}"          ms = 毫秒时间戳
__jda = "{cid}.{uid}.{t0}.{t0}.{t0}.1"   t0 = 秒级时间戳
__jdb = "{cid}.1.{uid}|1.{t0}"
__jdv = "{cid}|direct|-|none|-|{ms}"
```

实测自造 cookie 与真实 cookie 效果一致（各 3 轮 code=0），
故整套链路 **完全无需浏览器/JS 运行时**（见 `jd_session.py`）。

### 频率风控

同一会话短时间内请求过多会被标记，返回 HTTP 403 空响应。实测节奏（每页 1 次请求）：

| 页间间隔 | 结果 |
|---|---|
| 4 秒 | 连续 11 页正常，第 12 页 403，换一套 cookie 后恢复 |
| 5 秒 | 连续 8 页无异常 |
| 6 秒 | 连续 20 页无异常 |

→ 建议页间间隔 **≥6 秒**；命中 403 时**换一套 `__jd` cookie** 即可继续（无需重新握手）。
`jd_feed_pages.py` 已内置该重试逻辑。

---

## 12. 多页抓取

`python jd_feed_pages.py -n 20 -d 6`（见该文件头部注释的完整参数）。

要点：

- **每页都重新换取 token/rd**：rd 由服务端下发且与签名配套，不能跨页复用。
- 请求体 `page` 递增；`pagesize` 服务端不严格遵守（实测每页返回 20~30 条）。
- 结果位于响应 `data.data[]`，条目去重键为 `sku`。
- 末页判据：返回空列表，或本页全部为重复 sku。
- 实测该 feed 约 13 页见底（一次性连续抓取在末页前会开始返回重复数据）；
  20 页连续抓取累计 509 条（全部唯一 sku）。
- 命中 403（风控）/605（设备验证）时脚本自动新建 `JDSession` 重试，单页最多 3 次。
