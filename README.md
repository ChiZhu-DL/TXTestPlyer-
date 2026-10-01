# TX 视频播放 WebApp

糖心 Vlog 的第三方网页端：搜索、分类浏览、在线播放，附完整协议逆向实现。
仅供协议学习与安全研究，请勿用于任何违反服务条款或法律的用途。

## 文件说明

```
webapp/
├── tx_player.py     # 主程序（Flask 服务 + 协议加解密 + 图片/视频代理）
├── tx_player.html   # 前端页面（搜索/分类Tab/播放器/账号设置）
├── config.json      # 运行时自动生成：账号、API线路、img_key 等
└── img_debug/       # 封面解密失败的诊断样本与日志（自动生成）
```

## 环境要求与依赖安装

- Python 3.10+（开发时用的是 3.13）
- 安装四个依赖：

```bash
pip install flask requests pycryptodome pillow-heif
```

| 依赖 | 用途 |
|---|---|
| flask | Web 服务（8071 端口） |
| requests | 调用 API / 拉取图片与视频流 |
| pycryptodome | 业务协议 AES-256-CBC 解密 + 封面 .bnc AES-ECB 解密 |
| pillow-heif | HEIC/HEIF 封面转 JPEG（Chrome 不支持 HEIC） |

## 运行

```bash
cd webapp
python tx_player.py
```

启动后控制台会打印两个地址：

- 本机访问：`http://127.0.0.1:8071`
- 手机访问：`http://<局域网IP>:8071`（需同一 Wi-Fi；Windows 防火墙首次弹窗要点「允许」）

只允许本机访问时，在 `config.json` 加 `"listen_host": "127.0.0.1"`。

## 账号：自动游客号（无需抓包）

**默认不再内置任何账号。** 首次启动/首次请求时自动创建游客号：
随机生成 deviceId → `POST /cxapi/system/info`（token 传 `null_null`）→ 服务端自动建号并下发 token。

- **会话过期自动刷新**：任何接口返回 errorCode 2002 时，自动用同一 deviceId 重新拿 token 并重试（同 deviceId 幂等，还是同一个号）
- **一键换号**：网页「设置」→「新建游客号」，换新 deviceId 即全新账号
- **手动指定**：设置里也可填抓包得到的 token（如要用自己的会员号）

`config.json` 字段：

| 字段 | 说明 |
|---|---|
| `token` | 留空 = 自动游客号；也可填完整格式 `{token}_{uid}` 手动指定 |
| `device_id` | 游客号身份锚点，留空自动生成；同一 deviceId 永远对应同一账号 |
| `api_host` | API 线路，默认 `http://api.6hi6q6.com`；挂了可换 system/info 下发的其他线路 |
| `img_key` | 封面解密密钥，**由服务端下发并自动刷新**，一般不用手改 |
| `listen_host` | 监听地址，默认 `0.0.0.0` |

## 功能与接口对照

| 功能 | 接口 | 说明 |
|---|---|---|
| 首页分类 | `POST /cxapi/movie/block` | 参数 `{page, position}`；11 个 position（推荐/最新/热门/国产/原创/自制/网红/伦理/AV/动漫/暗黑推荐） |
| 搜索/推荐流 | `POST /cxapi/movie/search` | 推荐流参数已实测；**关键词搜索的 `keywords` 字段未验证**，搜不出结果需抓包修正 |
| 视频详情 | `POST /cxapi/movie/detail` | 57 个字段；`play_link` 为播放地址，`pay_type` 为付费类型 |
| 播放 | **新窗口独立播放页 `/play?id=`，视频 100% 直链**：`<video>`/hls.js 直连 CDN，服务器零视频流量。iOS Safari 原生直接播；桌面 Chrome 因 CDN 未开放 CORS（实测无 ACAO 头）无法网页播放，页面会引导复制直链给 VLC/PotPlayer（签名约 40 分钟有效） |
| 用户信息 | `POST /cxapi/user/info` | 设置页验证账号用 |

## 播放与内网穿透

- 点卡片 → 新窗口 `/play?id=` 播放页 → 直接请求 CDN 直链，**不经过本服务器**。
- 浏览器兼容矩阵：
  - **iOS Safari / 原生支持 HLS 的浏览器**：直接播放 ✅（媒体加载不受 CORS 限制）
  - **桌面 Chrome/Edge/Android Chrome**：CDN 无跨域许可，网页播放被浏览器拦截 ❌ —— 播放页会自动提示，复制直链到 VLC/PotPlayer 即可看
- **内网穿透**：服务监听 `0.0.0.0`，frp / 花生壳 / cloudflared 把 `8071` 端口映射出去即可。穿透页面上封面、搜索、详情全部正常；视频直链与页面协议（http/https）需一致，否则浏览器拦混合内容——iOS Safari 下若穿透是 HTTPS 而直链是 HTTP，也请用复制直链 → VLC 的方式。

## 协议要点（逆向结论）

1. **业务协议**：请求/响应体 = `IV(16B) + AES-256-CBC(gzip(JSON))`，
   key = `HMAC-SHA256("928547a24cbf62a315d8cf0f46d67a17", bytes.fromhex(reqid去掉连字符))`。
   `reqid`（小写头）每次请求随机生成、明文放在 HTTP 头里；请求头必须带 `version: 4.80.0`。
   注意：token 不在请求头，在 JSON body 里。
2. **封面 `.bnc`**：自定义加密图片，`AES-ECB(key=img_key, 零IV) + PKCS7`。
   `img_key` 由 `/cxapi/system/info` 响应的 `img_key` 字段下发（`im_key` 是 IM 用的）。
   解出来可能是 JPEG/PNG/GIF/WebP/AVIF/HEIC，HEIC 由 pillow-heif 转 JPEG。
3. **会员/付费**：完全由服务端判定（`is_vip`、`pay_type`、`layer_type`），非会员拿到的是试看 m3u8，客户端改包无意义。

## 常见问题

- **封面加载失败**：看 `img_debug/failures.log`，按 reason 分类（网络错误 / HTTP 状态 / 解密失败）。
  密文样本会存为 `fail_N.bin` 供分析；解密成功过的封面有内存缓存，翻页更快。
- **接口报 2002**：会话过期，程序已自动刷新游客 token 重试；若仍失败用「设置→新建游客号」。
- **手机打不开**：确认同一局域网、防火墙放行 8071、`listen_host` 为 `0.0.0.0`。
- **服务端返回明文(未加密)**：通常是 version 头不对或被风控，检查 `app_version`。

## 免责声明

本项目仅为学习 Flutter App 协议逆向的技术验证，所有数据来自自行抓包分析。
请勿将本程序用于任何商业用途或违反当地法律法规的用途，使用产生的一切后果由使用者自行承担。
