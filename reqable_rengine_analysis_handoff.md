# Reqable 登录请求 / rengine 加密与签名分析工作交接

> 生成时间：2026-07-03  
> 目标读者：完全没有当前会话上下文的 AI/分析员。  
> 注意：本文只保留必要技术细节，真实邮箱、设备信息、密码/密码派生值已尽量打码。用户已明确授权在其本机 Reqable 进程上进行 Frida hook 与登录请求明文捕获，使用测试账号，不涉及他人数据。

---

## 1. 总目标

用户想分析 Windows 版 Reqable 登录请求的生成过程，重点是：

1. 找到 `/account/login` 的真实 HTTP 请求。
2. 搞清楚 `Content-Type: application/rengine` body 是如何从登录 JSON 生成的。
3. 搞清楚 `signature` 请求头的生成算法。
4. 最终希望能复现 Reqable 登录接口的 rengine 加密/签名过程。

---

## 2. 环境与目标进程

### 目标应用

```text
C:\Program Files\reqable-app-windows-x86_64\Reqable.exe
C:\Program Files\reqable-app-windows-x86_64\data\app.so
C:\Program Files\reqable-app-windows-x86_64\flutter_windows.dll
```

### 运行进程

多次分析期间 Reqable PID 为：

```text
10524
```

如果继续分析，请先重新确认：

```powershell
Get-Process Reqable -ErrorAction SilentlyContinue | Select-Object Id,ProcessName,Path
```

### 工具

- Frida Python bindings 可用。
- Python 主环境在 Bash/PowerShell 下不同：Bash 环境无法导入 `idapro`。
- IDA portable 位于：

```text
C:\Users\rankin\Downloads\ida91\portable\windows
```

已执行过：

```powershell
C:\Users\rankin\Downloads\ida91\portable\windows\idapyswitch.exe --force-path C:\Users\rankin\AppData\Local\Programs\Python\Python314\python3.dll
```

用于配置 IDA Python 运行时。  
不过 `idat.exe -A -S...` 批处理反编译仍然失败/无有效 stdout，后续主要转为 Frida 动态分析。

---

## 3. 旧会话上下文处理方式

原 Claude 会话 JSONL：

```text
C:\Users\rankin_li\.claude\projects\C--Users-rankin-li\a6328642-243f-429a-9971-55d0c603e626.jsonl
```

该会话超出上下文，`/compact` 也失败。后续没有完整读入 JSONL，而是用脚本抽取关键段，避免把当前上下文撑爆。

---

## 4. 网络路径确认过程

### 已排除路径

最初尝试 hook：

- `reqable_http.dll`
- WinHTTP
- WinINet
- WS2_32 send/connect
- `reqable_cronet.dll` 公开 Cronet C API

结论：

1. 登录没有走 `reqable_http.dll` 的 HTTP builder。
2. 不走 WinHTTP/WinINet 明文层。
3. `WSASend` 只能看到 TLS ClientHello 与后续密文。
4. 公开 `reqable_cronet.dll` C API hook 没拿到登录 URL/method/body。

### 确认实际路径

`WSASend` 调用栈确认登录走的是 Dart/Flutter 自带网络栈：

- 目标域名：`app.reqable.com`
- 还会访问：`event.reqable.com`
- TLS ClientHello 中可见 SNI：`app.reqable.com`
- 后续都是 TLS 密文。

当前进程中 `flutter_windows.dll` 基址示例：

```text
0x7ff9a2a00000
```

某次 `WSASend` backtrace 相对 `flutter_windows.dll` offset：

```text
flutter_windows.dll + 0x6A797E
flutter_windows.dll + 0x6A7032
flutter_windows.dll + 0x6B4AE0
flutter_windows.dll + 0x733822
```

之前旧会话中也出现过类似偏移：`0x6d797e/0x6d7032/0x6e4ae0/0x743822`，但不同加载/版本/符号识别下偏移不完全一致，应以当前进程重新校准为准。

---

## 5. 已定位的 Dart SecureSocket / TLS 线索

通过 Dart native 函数表和 IDA 反编译曾定位到：

```text
SecureSocket_Connect       -> flutter_windows.dll + 0x6AFCD0
SecureSocket_FilterPointer -> flutter_windows.dll + 0x6B0610
SecureSocket_Handshake     -> flutter_windows.dll + 0x6B0180
SecureSocket_Init          -> flutter_windows.dll + 0x6AF9B0
Filter_Process             -> flutter_windows.dll + 0x6AA5A0
Filter_Processed           -> flutter_windows.dll + 0x6AA7B0
```

但实际 hook `Filter_Process` / `Filter_Processed` 没命中当前登录路径，说明这些 wrapper 不一定是当前登录实际执行点，或 Dart AOT 调用绕过了这些 wrapper。

曾误把 `off_180E8AF88` 当作普通 vtable 指针表，结果读到 ASCII 垃圾地址，导致 Frida access violation。不要沿这个误判继续。

---

## 6. 关键突破：内存扫描拿到 HTTP 明文请求

最终不是靠 TLS hook，而是一次性扫描进程内存关键词：

- `account/login`
- `/account`
- `login`
- `app.reqable.com`
- `password`
- `email`

脚本：

```text
C:\Users\rankin_li\AppData\Local\Temp\scan_reqable_heap_terms.py
C:\Users\rankin_li\AppData\Local\Temp\scan_terms_args.py
C:\Users\rankin_li\AppData\Local\Temp\dump_reqable_memory.py
C:\Users\rankin_li\AppData\Local\Temp\parse_reqable_request_at.py
```

通过扫描得到 `/account/login` 的完整 HTTP 明文请求缓冲区，说明 Dart/TLS 加密前的 HTTP 请求会在内存里短暂驻留。

---

## 7. 未注册账号 / 邮箱检查请求样本

第一次测试账号未注册，服务端事件为：

```text
account_email_login_unregister
```

### 请求头

```http
POST /account/login HTTP/1.1
user-agent: Dart/3.3 (dart:io)
accept-encoding: gzip
channel: app
content-type: application/rengine
app-id: com.reqable.windows
timestamp: 1783059314229
content-length: 80
app-locale: zh-CN
app-code: 202
host: app.reqable.com
signature: 8dc8fd06054fb0eb985e586ec254437f80fd6b7f57aeb45e1b4c80fbf066e650
app-version: 3.2.4
app-extension: zip
```

`host-device` 是设备信息 base64，已省略。

### body，80 bytes

```text
6fa0f0ce3285a39362cb4318f7c9e9a8b9a12021e4c64eb6cc38433b71943e04a6da5874140a0f15c3a5ad22c8947d1a335b30b5060f6c36de15c1721949728179e611595f327a3595cdc07337bb6da4
```

### 发送前 JSON 明文片段

```json
{"_email":"<email>","device_name":"Windows 11 Pro"}
```

这个明文长度 pad 后对应 80 bytes ciphertext，因此也符合 AES/CBC/PKCS7 假设。

---

## 8. 已注册账号登录请求样本 A

用户后来用已注册测试账号登录。

事件确认：

```text
account_email_login_authorized
```

### 请求头

```http
POST /account/login HTTP/1.1
user-agent: Dart/3.3 (dart:io)
accept-encoding: gzip
channel: app
content-type: application/rengine
app-id: com.reqable.windows
timestamp: 1783061424791
content-length: 96
app-locale: zh-CN
app-code: 202
host: app.reqable.com
signature: be84e253566715046c05fafcb9a239103bf8a6a3d0e37ced66b4ffb6c5786ca5
app-version: 3.2.4
app-extension: zip
```

### body，96 bytes

```text
af716a07a60a2878146bdd8660040495a3d908a71b01aeb75d398115205b4fc0bbaa92ad926aee728c7a29347c80aa7fde8f14b6bcd7ce4ca37b8c05c2099de0cdd3c72f418600522d7043708e2af32cf80998c8d024b7a770a9621c04722a9d
```

### 发送前 JSON 明文结构

真实邮箱和 password 派生值已打码：

```json
{"email":"<email>","password":"<base64-24-chars>"}
```

观察到的 `password` 字段特点：

- 不是用户输入的原始密码。
- 是 24 字符 base64。
- base64 解码后为 16 bytes。
- 非常像 MD5/AES block/固定长度密码摘要。

当时某次捕获的 base64 解码长度：

```text
16 bytes
```

不要在交接中公开真实 password 派生值；如需复现算法，请重新授权后重新捕获。

### 明文长度与密文长度

对样本 A，明文 JSON 长度：

```text
81 bytes
```

`AES/CBC/PKCS7` padding 后为：

```text
96 bytes
```

这与 `content-length: 96` 完全一致。

结论：

```text
application/rengine body 基本可以确认是登录 JSON 经 AES/CBC/PKCS7 加密后的 ciphertext。
```

---

## 9. 已注册账号登录请求样本 B

用户退出后重新登录，又抓到一组新请求。

### 请求头

```http
POST /account/login HTTP/1.1
timestamp: 1783062656230
content-length: 96
signature: d5b5882a72f6ef8fab18523d4e0e021fbdf4b15fc0e58b43b1df1153a39ea3c3
```

其它头部同样包括：

```http
user-agent: Dart/3.3 (dart:io)
channel: app
content-type: application/rengine
app-id: com.reqable.windows
app-locale: zh-CN
app-code: 202
host: app.reqable.com
app-version: 3.2.4
app-extension: zip
```

### body，96 bytes

```text
4e89edf59c85d1819e2724aa9787f2195d13129239f23c80f0dd0b2bc10d93c0af36592eb0cd9df097a9f7b6107dfe8bfb00ef8b6bdda55807a52f18c4c52579368713f80136ea7b2f58396c32bc4cf875dc09bc6a96cf1bd5360af9502
```

事件确认成功：

```text
account_email_login_authorized
```

---

## 10. rengine / crypto 重要线索

### 关键字符串

内存和 `data\app.so` 中都出现过：

```text
AES/CBC/PKCS7
AES/CBC
AES
PKCS7
reqable-api-v2-wonder
reqable-api-wonder
application/rengine
```

在 `data\app.so` 中：

```text
reqable-api-v2-wonder at app.so offset 0x6ca528
reqable-api-wonder    at app.so offset 0x6e920c
application/rengine   at app.so offset 0x6542d0
```

内存里曾在登录 JSON 附近观察到形如：

```text
<email>-api-v2-wonder-1783061424
AES/CBC/PKCS7
```

其中：

```text
header timestamp: 1783061424791
seconds:          1783061424
```

说明 `<email>-api-v2-wonder-<timestamp_seconds>` 几乎肯定参与 key/iv/signature 派生。

### signature 特点

`signature` 是 64 hex chars，看起来是 SHA-256 输出。

样本：

```text
8dc8fd06054fb0eb985e586ec254437f80fd6b7f57aeb45e1b4c80fbf066e650
be84e253566715046c05fafcb9a239103bf8a6a3d0e37ced66b4ffb6c5786ca5
d5b5882a72f6ef8fab18523d4e0e021fbdf4b15fc0e58b43b1df1153a39ea3c3
```

### 已尝试但未命中的 AES 派生候选

已用 PowerShell/.NET `System.Security.Cryptography.Aes` 本地验证过多组常见候选：

- key = `sha256(<email>-api-v2-wonder-<sec>)`
- key = `md5(<email>-api-v2-wonder-<sec>)`
- key = sha256 前 16 / 后 16 / 全 32
- key = utf8 前 16 / 后 16 / 前 32 / 后 32
- iv = zero / md5 / sha256 前 16 / sha256 后 16 / utf8 截断
- 也测试了这些源字符串：
  - `reqable-api-v2-wonder`
  - `reqable-api-wonder`
  - `api-v2-wonder-<sec>`
  - `reqable-api-v2-wonder-<sec>`
  - `<email>-api-v2-wonder-<sec>`
  - `<email>-reqable-api-v2-wonder-<sec>`

结果：

```text
NO_MATCH
```

所以 key/iv 派生不是最朴素的 sha/md5 截断组合，或者加密前 JSON 还有额外变换/排序/不可见字符，或者 iv/key 来源不是这些直接组合。

---

## 11. 二进制字符串搜索结果

对 `data\app.so` 搜索：

```text
application/rengine  1 hit  offset 0x6542d0
app-extension        1 hit  offset 0x53f400
signature           26 hits
host-device          1 hit  offset 0x519170
account/login        1 hit  offset 0x4bedc0
app-id               1 hit  offset 0x5ce610
reqable-api-v2-wonder 1 hit offset 0x6ca528
reqable-api-wonder    1 hit offset 0x6e920c
```

对 `flutter_windows.dll` 搜索：

```text
signature 36 hits, 多为通用 SSL/PNG/BoringSSL 字符串
rengine   52 hits, 多为 Flutter engine embedder 字符串
```

结论：业务逻辑主要在 Dart AOT `data\app.so`，不是 `flutter_windows.dll`。

---

## 12. Frida 脚本清单与用途

所有脚本位于：

```text
C:\Users\rankin_li\AppData\Local\Temp\
```

### 已用且有价值

```text
scan_reqable_heap_terms.py
```

扫描固定关键词，首次发现 `/account/login` HTTP 明文请求。

```text
dump_reqable_memory.py
```

按地址 dump 指定内存区域。

```text
parse_reqable_request_at.py
```

从给定地址附近查找 `POST `，解析 HTTP header/body，输出 body hex。

```text
scan_terms_args.py
```

按命令行传入关键词扫描内存，常用于找 email/password/AES/key material。

```text
hook_wsasend_bt2.py
```

重新校准当前 `WSASend` 调用栈，确认 TLS 发送链路和 `flutter_windows.dll` offset。

### 有问题或效果不佳

```text
monitor_rengine_access.py
```

最初版本读取 `details.range.base`，Frida API 中该字段为 undefined，报错。

```text
monitor_rengine_access2.py
```

修复了 API 字段，但 MemoryAccessMonitor 只盯启动时已有页，不适合新分配 JSON；捕获效果差。

```text
monitor_copy_crypto.py
```

Frida JS 中 `hexdump` 是保留/内置名称，定义同名函数导致：

```text
TypeError: cannot define variable 'hexdump'
```

```text
monitor_copy_crypto2.py
```

修复为 `hexDumpSmall`。用户最后说界面卡住，要求停下保存成果。已停止后台任务，还没用它完成有效登录采集。

---

## 13. 最后一轮状态

用户说界面卡住，要求停止当前任务并保存成果。

已停止后台任务：

```text
bzo0yu9uw
```

对应命令：

```text
python C:/Users/rankin_li/AppData/Local/Temp/monitor_copy_crypto2.py 10524
```

不要假设 monitor 仍在运行。

---

## 14. 下一步建议

如果继续分析 rengine 算法，建议按优先级：

### 方向 A：继续 Frida 动态 hook Dart AOT 内部复制/加密点

启动已修复脚本：

```text
C:\Users\rankin_li\AppData\Local\Temp\monitor_copy_crypto2.py
```

然后让用户退出/重新登录。  
目标是捕获包含：

```text
"password"
AES/CBC/PKCS7
account/login
application/rengine
api-v2-wonder
reqable-api-v2-wonder
```

的拷贝调用栈与参数。

注意：如果脚本输出过大，要只读取有限行并做打码。

### 方向 B：在 `data\app.so` 里静态追踪字符串引用

重点字符串 offset：

```text
account/login           0x4bedc0
application/rengine     0x6542d0
reqable-api-v2-wonder   0x6ca528
reqable-api-wonder      0x6e920c
host-device             0x519170
app-id                  0x5ce610
```

需要找这些字符串在 Dart AOT snapshot 中的引用关系。传统 IDA 对 Dart AOT 不一定友好，可能更适合：

- Dart AOT snapshot tooling
- strings + xref heuristics
- Frida runtime tracing
- 直接 hook Dart runtime allocation/copy/hash/crypto functions

### 方向 C：hook 加密库 API

目前没有证据使用 Windows CNG/OpenSSL 导出 API；`data\app.so` 中未搜到明显：

```text
EVP_Encrypt
AES_set_encrypt_key
AES_cbc_encrypt
```

说明 AES 可能是 Dart package / AOT 内联实现，而非系统 crypto API。

仍可尝试：

- hook `bcrypt!BCryptEncrypt`，但之前尚未确认命中。
- hook 内存中 `AES/CBC/PKCS7` 字符串附近的调用链。
- hook 常见 Dart package 的 block cipher 实现特征。

### 方向 D：收集更多样本做差分

需要至少 3 组同一账号、同一 password、不同 timestamp 的：

- 明文 JSON（打码保存 email/password 结构即可，若要复现算法需本地保留真实值）
- timestamp ms / seconds
- body ciphertext
- signature

目前已有 body/signature/timestamp 两组注册登录样本，但真实明文敏感字段已不在本文完整公开，若要做离线复现应在用户授权下重新捕获并只存本地。

---

## 15. 安全与隐私注意事项

1. 用户已授权对其本机 Reqable 进程做 Frida hook，且使用测试账号。
2. 仍应避免在聊天或文档中公开真实邮箱、原始密码、可复用 token。
3. `password` 字段里的 base64 虽非原始密码，但可能等价于认证材料，应视为敏感。
4. 如果继续保存样本，建议本地加密保存或只保存打码版本。
5. 不要把这些数据发往外部服务。

---

## 16. 当前最重要结论（一句话版）

Reqable Windows 登录请求 `/account/login` 在 Dart/Flutter 网络栈中发送，TLS 前内存里能看到完整 HTTP 明文；`application/rengine` body 几乎可以确认是登录 JSON 经 `AES/CBC/PKCS7` 加密后的 ciphertext，key/signature 生成与 timestamp 相关的 `reqable-api-v2-wonder-*`/`reqable-api-wonder` 材料、`signature`/SHA-256 相关，但简单 sha/md5 截断派生 key/iv 已测试不匹配，下一步应动态 hook Dart AOT 中 JSON 到 AES 加密的拷贝/调用链。

---

## 17. 2026-07-03 续作新增成果：无 `app.so` 模块名但找到了 Dart 代码/数据映射

后续继续分析时，用户明确要求以后需要登录时“直接启动脚本，然后让他退出/登录”，不要每次先询问是否启动。

### 17.1 当前进程模块现象

新一轮 Reqable PID 曾为：

```text
5376
```

Frida `Process.enumerateModules()` 中没有名为 `app.so` 的模块。实际模块列表只显示：

```text
Reqable.exe
flutter_windows.dll
reqable_netbare.dll
reqable_http.dll
reqable_cronet.dll
各类 Flutter plugin dll
```

但全局内存扫描证明 Dart AOT/业务代码和只读字符串确实映射在匿名内存区域里，例如旧 PID 10524 时观察到：

```text
代码区：r-x@0x1dc850bc000
只读字符串区：r--@0x1dc84910000
只读字符串区：r--@0x1dc9a850000
```

因此后续不要依赖模块名 `app.so`，而应按匿名 `r-x`/`r--` 区域和关键字符串定位。

### 17.2 新增/更新脚本

新增了这些低影响脚本：

```text
C:\Users\rankin_li\AppData\Local\Temp\enum_reqable_modules.py
C:\Users\rankin_li\AppData\Local\Temp\monitor_reqable_static_strings_global.py
C:\Users\rankin_li\AppData\Local\Temp\focused_static_scan_dump.py
C:\Users\rankin_li\AppData\Local\Temp\extract_rengine_requests.py
C:\Users\rankin_li\AppData\Local\Temp\capture_login_key_material.py
C:\Users\rankin_li\AppData\Local\Temp\dump_exact_addr.py
C:\Users\rankin_li\AppData\Local\Temp\test_exact_login_aes.ps1
```

用途：

- `monitor_reqable_static_strings_global.py`：不依赖 `app.so` 模块名，扫描所有可读内存中的 rengine/key/signature 字符串，只对命中的少量页面启用 `MemoryAccessMonitor`。
- `focused_static_scan_dump.py`：扫描并 dump 关键字符串周边内容。
- `extract_rengine_requests.py`：从当前内存中抽取 `POST /...` rengine 请求、timestamp、signature、body。
- `capture_login_key_material.py`：每 100ms 扫描 `/account/login`、`reqable-api-v2-wonder-*`、登录 JSON、`/account/fetch`，用于一次登录时同时抓取明文、密文和 key-material。
- `dump_exact_addr.py`：只 dump 指定地址的短窗口，不把整页敏感内存持久化。
- `test_exact_login_aes.ps1`：用 .NET AES 测试精确登录明文/密文的候选 key/iv。

注意：尝试把完整内存页保存为 `login_key_region.bin` 被权限分类器拒绝，因为可能持久化登录秘密。后续仍应避免把整页原始内存写盘。

---

## 18. 2026-07-03 续作新增成果：静态字符串页访问监控

`monitor_reqable_static_strings_global.py` 命中过关键字符串：

```text
reqable-api-v2-wonder
reqable-api-wonder
application/rengine
account/login
host-device
app-id
signature
AES/CBC/PKCS7
AES/CBC
PKCS7
```

旧 PID 10524 时捕获到一些有价值的访问点：

```text
读取 application/rengine 附近：
from r-x@0x1dc850bc000+0xcada95
address r--@0x1dc84f2e000+0x362c0

读取 signature 附近：
from r-x@0x1dc850bc000+0xe9aac0
address r--@0x1dc84910000+0x4b7ef0

读取 reqable-api-v2-wonder 附近：
from r-x@0x1dc850bc000+0x6a04
address r--@0x1dc84f65000+0x75940

读取 PKCS7 / AES 相关附近：
from r-x@0x1dc850bc000+0x6a04
address r--@0x1dc84e2a000+0x6fe00

from r-x@0x1dc850bc000+0xd408f8
address rw-@0x1dc8cc80000+0x491b0

from r-x@0x1dc850bc000+0x266b93
address rw-@0x1dc8cc80000+0x4ad60
```

这些 offset 都是匿名 Dart 代码映射内的 offset，不是 `flutter_windows.dll` offset。后续若复现，需要在当前 PID 中重新扫描得到新的匿名代码基址，再用相对 offset 对齐。

---

## 19. 2026-07-03 续作新增成果：timestamp key-material 明确出现

`focused_static_scan_dump.py` 在登录/账号请求后发现内存中直接出现：

```text
reqable-api-v2-wonder-1783068889339
reqable-api-v2-wonder-1783068889
reqable-api-v2-wonder-1783068888863
reqable-api-v2-wonder-1783068888
```

其中 `1783068889339` 等是请求 header 的 millisecond timestamp，`1783068889` 是对应 seconds timestamp。

后续一次 `/account/login` 精确捕获中也观察到同样模式，且 key-material 与明文 JSON 紧邻：

```text
reqable-api-v2-wonder-1783069905789
reqable-api-v2-wonder-1783069905
```

结论更新：

```text
rengine 加密/签名流程中明确生成 reqable-api-v2-wonder-{timestamp_ms}
和 reqable-api-v2-wonder-{timestamp_seconds} 两种字符串。
```

这比旧结论中 `<email>-api-v2-wonder-{seconds}` 更可靠；旧结论可能来自内存相邻字符串误读或另一个中间材料。当前最强证据是 `reqable-api-v2-wonder-{timestamp}`。

---

## 20. 2026-07-03 续作新增成果：当前精确登录样本 C

使用 `capture_login_key_material.py`，在 PID 5376 中成功同时抓到：

- `/account/login` HTTP 明文请求；
- 同一次请求的 timestamp/signature/body；
- 同一次请求的登录 JSON 明文；
- 同一内存窗口中的 `reqable-api-v2-wonder-{timestamp}` key-material。

### 20.1 `/account/login` 请求样本 C

```http
POST /account/login HTTP/1.1
timestamp: 1783069905789
content-length: 96
host: app.reqable.com
content-type: application/rengine
signature: 9147f4475f51f96ecb86c75874fe747d53a6b0a5962a0c28c201c77f11763090
```

body，96 bytes：

```text
5a59f3a9654ffb4e1274a05a26ed9b83f88475ff52e49deb60d5a0b8458063a46c47edb2f1aa04d8ae3cdc43738c07a9a1b257673c58343ba340becc4a1c182da060108dcc09d97feffb280c5cfa2a0122587a6d32014b62141f63a293586372
```

### 20.2 同次登录 JSON 明文

已确认明文结构为：

```json
{"email":"<email>","password":"<base64-24-chars>"}
```

本次实际明文长度：

```text
81 bytes
```

PKCS7 padding 后：

```text
96 bytes
```

与 rengine body 完全一致。

真实邮箱和 password 派生值没有写入本文；`password` 字段虽然不是原始密码，但应视为等价敏感材料。

### 20.3 同次 key-material

在 JSON 后方同一短窗口中观察到：

```text
reqable-api-v2-wonder-1783069905789
reqable-api-v2-wonder-1783069905
```

其中：

```text
header timestamp: 1783069905789
seconds:          1783069905
```

这说明这两个字符串与当前 login 请求强绑定，不是历史残留。

---

## 21. 2026-07-03 续作新增成果：对照请求样本

同一阶段还抽到 `/account/fetch` 对照样本：

```http
POST /account/fetch HTTP/1.1
timestamp: 1783069893497
content-length: 16
signature: ba11880347cb9322526ec0af313f1680c358209cc34b85ab33a13ebce0bc0248
```

实际密文 body：

```text
a33209f906278a260dbac7099018ffa6
```

注意：内存里有时还会出现同 timestamp/signature 但 body 为全 0 的缓存区：

```text
00000000000000000000000000000000
```

这应视为发送后被清零或复用的 buffer，不应拿来做算法验证。

---

## 22. 2026-07-03 续作新增成果：最新 AES 候选测试

针对样本 C，用精确明文/密文/timestamp 测试了大量候选：

- `reqable-api-v2-wonder`
- `reqable-api-wonder`
- `reqable-api-v2-wonder-1783069905789`
- `reqable-api-v2-wonder-1783069905`
- `reqable-api-wonder-1783069905789`
- `reqable-api-wonder-1783069905`
- timestamp ms / seconds
- email
- password 派生值
- email/password/timestamp 各种拼接
- MD5/SHA1/SHA256/SHA384/SHA512 raw、hex、截断
- AES-CBC / AES-ECB
- zero IV 与各种 hash/substr IV

初步结果：未命中。长时间搜索任务曾输出：

```text
keys=2058 ivs=520 ptLen=81
```

但未发现匹配，随后手动停止以避免无意义消耗。

结论：

```text
reqable-api-v2-wonder-{timestamp} 很可能是签名/派生流程的输入，
但不是简单截断/hash 后直接作为 AES key/iv。
```

---

## 23. 当前下一步建议更新

旧建议中的全局 `memcpy`/`memmove` hook 已证明会导致 UI 卡顿，除非用户明确接受风险，否则不要再使用。

优先建议：

1. 继续使用低影响、定点脚本。
2. 在登录前启动监控，然后让用户退出/登录。
3. 捕获 JSON/key-material 出现时，动态记录访问它们的匿名 `r-x` 代码 offset。
4. 围绕已发现的匿名代码 offset 做更窄 hook，而不是全局 copy hook。
5. 尝试从 Dart AOT 匿名代码中定位：
   - JSON 明文被传入 AES 前的调用点；
   - key/iv 派生函数；
   - signature SHA-256/HMAC 输入拼接点。

下一步最有价值的脚本方向：

```text
启动一个“先扫描 login JSON/key-material，命中后只监控这些页访问”的 MemoryAccessMonitor，
输出 fromLoc 的匿名 r-x offset 与 backtrace。
```

目标是拿到“谁读取了登录 JSON 和 reqable-api-v2-wonder-{timestamp}”，而不是继续盲猜 AES key。
