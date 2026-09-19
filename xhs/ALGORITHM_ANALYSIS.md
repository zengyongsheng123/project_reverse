# 小红书 Web x-s 算法分析

## 结论

当前实现已经封装在 `xhs_full_signer.py`，入口函数是：

- `sign_xs(uri, data, a1_value, ...)`：生成 `x-s`
- `build_x_s_common(...)`：生成 `x-s-common`
- `build_signed_headers(url, body, cookies, headers, ...)`：刷新请求头
- `post_homefeed()`：使用内置 demo 样本完成真实请求

实测结果：

- 本地结构校验通过：`XYS_`、`mns0301_`、`x5`、payload 长度均一致
- 真实接口通过：`HTTP 200`，响应 `success=true`、`code=0`

## x-s 外层结构

`x-s` 格式：

```text
XYS_ + custom_base64(JSON.stringify(sign_obj))
```

外层 JSON 字段：

```json
{
  "x0": "4.4.3",
  "x1": "xhs-pc-web",
  "x2": "Windows",
  "x3": "mns0301_...",
  "x4": "object",
  "x5": "md5(uri + compact_json(body))"
}
```

关键点：

- `x4` 固定是字符串 `"object"`，不是请求 body 对象。
- `x5` 是 `uri + body` 的 MD5，其中 body 必须是无空格紧凑 JSON。
- 外层 base64 使用自定义 alphabet：`ZmserbBoHQtNP+wOcza/LpngG8yJq42KWYj0DSfdikx3VT16IlUAFM97hECvuRX5`。

## x3 / mns0301 结构

`x3` 格式：

```text
mns0301_ + custom_x3_base64(xor(payload, HEX_KEY))
```

关键常量：

- payload 明文长度：`144`
- `x3` 完整长度：`200`
- 版本字节：`[121, 104, 96, 41]`
- x3 base64 alphabet：`MfgqrsbcyzPQRStuvC7mn501HIJBo2DEFTKdeNOwxWXYZap89+/A4UVLhijkl63G`

payload 字段顺序：

```text
0..3     version
4..7     random seed little-endian
8..15    当前毫秒时间戳 little-endian
16..23   page load 毫秒时间戳
24..27   sequence
28..31   window props length
32..35   uri/body 拼接串长度
36..43   x5 md5 前 8 字节 xor seed_byte
44       a1 长度
45..96   a1，最多 52 字节，不足补 0
97       app_id 长度
98..107  app_id，最多 10 字节，不足补 0
108..122 环境检查表
123..126 A3 prefix: [2, 97, 51, 16]
127..142 hash(timestamp_bytes + path_md5_bytes) xor seed_byte
143      末尾补齐字段
```

实现里会强校验 payload 长度，避免静默生成错误签名。

## 自定义 hash

`x3` 尾部使用一个 128-bit 的自定义 hash：

- 初始 IV：`(1831565813, 461845907, 2246822507, 3266489909)`
- 输入：`timestamp_ms_le_8 + md5(uri)_bytes`
- 按 8 字节 block 做 little-endian unpack
- 使用 32 位加法、异或和循环左移混合
- 输出 16 字节 little-endian，再和 `seed_byte` 异或

## x-s-common

`x-s-common` 是另一层自定义 base64 编码的 JSON。当前单文件包含：

- `X_S_COMMON_SEED`：从还原文件中提取的长种子串
- `_crc32_variant()`：还原 JS 侧 `x9` 计算
- `_x12()`：`当前时间戳;首次访问时间戳`
- `build_x_s_common()`：生成完整 header

真实请求优先使用抓包里的 `CAPTURED_X_S_COMMON`，这是为了保证当前样本稳定通过；如果该常量置空，或显式要求刷新，会自动走动态生成：

```python
post_homefeed(refresh_common=True)
```

## 请求全流程

1. 准备 `url`、`body`、`cookies["a1"]`。
2. 取 `uri = urlparse(url).path`。
3. 当前毫秒时间写入 `x-t`。
4. `sign_xs(uri, body, a1, timestamp=x_t / 1000)` 生成 `x-s`。
5. 使用 `x-s-common`、`x-rap-param`、cookie 等请求头发起 POST。

## 验证点

`xhs_full_signer.py` 运行时会先执行本地校验：

- `x-s` 前缀是 `XYS_`
- 解码后 `x5 == md5(uri + compact_json(body))`
- `x3` 前缀是 `mns0301_`
- `x3` 长度是 `200`
- 解密后 payload 长度是 `144`
- payload 版本字节是 `[121, 104, 96, 41]`
- `x4 == "object"`

随后再发起真实请求并用 loguru 输出状态码、响应大小和 API 业务码。

## 使用方式

运行环境：

- Python 3.9+
- `requests`
- `loguru`

安装依赖：

```bash
pip install requests loguru
```

运行：

```bash
python xhs_full_signer.py
```

作为模块调用：

```python
from xhs_full_signer import build_signed_headers, DEFAULT_COOKIES

headers = build_signed_headers(url, body, DEFAULT_COOKIES)
```
