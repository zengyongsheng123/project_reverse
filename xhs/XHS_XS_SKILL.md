---
name: xhs-xs-recover
description: Use when restoring, validating, or packaging Xiaohongshu Web x-s/x-s-common signing logic into a pure Python request flow.
---

# XHS x-s Recover

Use this skill for Xiaohongshu Web signing tasks where the goal is to reproduce `x-s`, validate request headers, or package the algorithm for repeatable requests.

## Workflow

1. Start from a real captured request, not a guessed endpoint.
2. Fix the sample inputs: `url path`, compact JSON body, `a1`, `x-t`, and current `x-s`.
3. Decode `x-s` before coding:
   - outer prefix must be `XYS_`
   - JSON must contain `x0/x1/x2/x3/x4/x5`
   - `x5` must equal `md5(uri + compact_json(body))`
   - `x3` must start with `mns0301_`
4. Recover `x3` as a 144-byte payload:
   - custom x3 base64 decode
   - xor with static `HEX_KEY`
   - check version bytes `[121, 104, 96, 41]`
5. Implement pure Python signing and keep browser/runtime-only state as explicit inputs or conservative defaults.
6. Validate in two layers:
   - local decode/checkpoint validation
   - live request validation against the captured endpoint

## Non-Obvious Rules

- `x4` is the literal string `"object"`.
- The signed content is `uri + compact_json(body)`, not full URL.
- Body JSON must use `separators=(",", ":")` and `ensure_ascii=False`.
- `x-t` must align with the timestamp used inside `x3`.
- For stable live tests, keep captured `x-s-common` and `x-rap-param` first; refresh them only after the `x-s` path is proven.
- Treat cookie/session failures separately from signature failures.

## Expected Artifact

Produce a single callable module with:

- `sign_xs()`
- `build_x_s_common()`
- `build_signed_headers()`
- local validation helpers
- one live request entrypoint using loguru logs

Stop only after `py_compile`, local checkpoint validation, and a live request have all passed or the remaining blocker is explicitly identified.
