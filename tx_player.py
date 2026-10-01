# -*- coding: utf-8 -*-
"""
TX 视频搜索/播放 · 网页版 (端口 8071)
====================================
功能：
  - 网页搜索视频（/cxapi/movie/search）
  - 点开即播（/cxapi/movie/detail 取 play_link → 服务端代理 m3u8/ts/密钥 → hls.js 播放）
  - 账号(token/deviceId) 内置默认值，网页右上角「设置」可随时更换，持久化到 config.json

协议（与抓包一致）：
  AES-256-CBC(gzip(json))，key = HMAC-SHA256("928547a24cbf62a315d8cf0f46d67a17",
  bytes.fromhex(reqid去连字符))，IV 前置 16 字节；头名小写 reqid。

运行：
  python tx_player.py
  浏览器打开 http://127.0.0.1:8071
"""
import gzip
import hmac
import hashlib
import json
import os
import random
import re
import string
import time
import uuid
from urllib.parse import quote

import requests
from flask import Flask, request, jsonify, Response, stream_with_context
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ---------------------------------------------------------------- 配置
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

DEFAULT_CONFIG = {
    # 账号：留空则首次调用时自动创建游客号（deviceId 随机生成，服务端建号发 token）
    # 会话过期(2002)自动用同 deviceId 刷新；也可网页「设置」里手动填 token 或一键新建游客号
    "token": "",
    "device_id": "",
    "api_host": "http://api.6hi6q6.com",
    "app_version": "4.80.0",
    # .bnc 图片 AES-ECB 密钥，由 /cxapi/system/info 下发（img_key 字段），会自动刷新
    "img_key": "525202f9149e061d",
}

DART_UA = ("Mozilla/5.0 (Linux; U; Android 2.1; en-us; Nexus One Build/ERD62) "
           "AppleDart/530.17 (KHTML, like Gecko) Version/4.0 Mobile Safari/530.17")
PLAYER_UA = "ExoPlayer"           # m3u8/ts 拉流用的 UA（与抓包一致）
PLAYER_REFERER = "http://www.qq.com"
HMAC_KEY = b"928547a24cbf62a315d8cf0f46d67a17"


def load_config():
    cfg = dict(DEFAULT_CONFIG)
    if os.path.exists(CONFIG_PATH):
        try:
            cfg.update(json.load(open(CONFIG_PATH, encoding="utf-8")))
        except Exception:
            pass
    return cfg


def save_config(cfg):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


CFG = load_config()

# ---------------------------------------------------------------- 协议加解密
def aes_key(reqid: str) -> bytes:
    return hmac.new(HMAC_KEY, bytes.fromhex(reqid.replace("-", "")), hashlib.sha256).digest()


def encrypt_raw(plaintext: bytes, reqid: str) -> bytes:
    iv = uuid.uuid4().bytes
    cipher = AES.new(aes_key(reqid), AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(gzip.compress(plaintext), 16))


def decrypt_raw(data: bytes, reqid: str) -> bytes:
    iv, body = data[:16], data[16:]
    cipher = AES.new(aes_key(reqid), AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(body), 16)
    try:
        pt = gzip.decompress(pt)
    except OSError:
        pass
    return pt


def create_guest(force_new_device=False):
    """创建/刷新游客账号：POST /cxapi/system/info（token=null_null，服务端按 deviceId 建号）。
    同 deviceId 幂等（同一账号）；force_new_device=True 换新设备即新账号。
    建号参数与 tx_api.py 对齐：country 走随机池，降低风控关联。"""
    if force_new_device or not CFG.get("device_id"):
        CFG["device_id"] = "".join(random.choices(string.hexdigits.lower(), k=16))
    reqid = str(uuid.uuid4())
    payload = {
        "token": "null_null",
        "deviceId": CFG["device_id"],
        "language": "zh",
        "data": {
            "app_code": "china_1",
            "clipboard_text": "",
            "country": random.choice(["CN", "US", "JP", "RU"]),
            "channel_code": "channel://ozxxoo3",
            "captcha_key": None,
            "captcha_value": None,
        },
    }
    body = encrypt_raw(json.dumps(payload, ensure_ascii=False).encode("utf-8"), reqid)
    headers = {
        "user-agent": DART_UA,
        "time": str(int(time.time() * 1000)),
        "version": CFG["app_version"],
        "devicetype": "android",
        "reqid": reqid,
        "content-type": "application/x-www-form-urlencoded",
        "accept-encoding": "gzip",
        "host": CFG["api_host"].split("://", 1)[-1],
        "connection": "close",
    }
    try:
        r = requests.post(CFG["api_host"] + "/cxapi/system/info", data=body, headers=headers, timeout=15)
        obj = json.loads(decrypt_raw(r.content, reqid).decode("utf-8"))
    except Exception as e:
        return False, f"游客建号失败: {type(e).__name__}: {e}"
    t = (obj.get("data") or {}).get("token") or {}
    if obj.get("status") != "y" or not t.get("token") or not t.get("user_id"):
        return False, f"游客建号被拒: status={obj.get('status')} msg={obj.get('msg','')}"
    CFG["token"] = f"{t['token']}_{t['user_id']}"
    if (obj.get("data") or {}).get("img_key"):
        CFG["img_key"] = obj["data"]["img_key"]
    save_config(CFG)
    print(f"[acct] 游客账号就绪: uid={t['user_id']} username={t.get('username')} "
          f"deviceId={CFG['device_id']} (新建={force_new_device})", flush=True)
    return True, {"uid": t["user_id"], "username": t.get("username"),
                  "nickname": t.get("nickname", ""), "is_vip": t.get("is_vip"),
                  "device_id": CFG["device_id"], "token": CFG["token"]}


def _post_encrypted(path: str, payload: dict, timeout=15):
    """底层加密请求：payload 为完整 JSON（含 token/deviceId），返回解密后的 dict 或抛异常"""
    reqid = str(uuid.uuid4())
    body = encrypt_raw(json.dumps(payload, ensure_ascii=False).encode("utf-8"), reqid)
    headers = {
        "user-agent": DART_UA,
        "time": str(int(time.time() * 1000)),
        "version": CFG["app_version"],
        "devicetype": "android",
        "reqid": reqid,
        "content-type": "application/x-www-form-urlencoded",
        "accept-encoding": "gzip",
        "host": CFG["api_host"].split("://", 1)[-1],
        "connection": "close",
    }
    r = requests.post(CFG["api_host"] + path, data=body, headers=headers, timeout=timeout)
    raw = r.content
    # 服务端异常时可能直接回明文 JSON
    if raw[:1] == b"{":
        return {"__plain__": True, "obj": json.loads(raw.decode("utf-8", "replace"))}
    if len(raw) < 32 or len(raw) % 16:
        raise RuntimeError(f"响应格式异常 (len={len(raw)}, http={r.status_code})")
    return json.loads(decrypt_raw(raw, reqid).decode("utf-8"))


def api_post(path: str, data: dict, timeout=15):
    """调用加密接口：无账号先自动建游客号；会话过期(2002)自动刷新后重试一次"""
    if not CFG.get("token"):
        ok, info = create_guest()
        if not ok:
            return False, {"error": info}
    payload = {
        "token": CFG["token"],
        "deviceId": CFG["device_id"],
        "language": "zh",
        "data": data,
    }
    retried = False
    while True:
        try:
            obj = _post_encrypted(path, payload, timeout)
        except requests.RequestException as e:
            return False, {"error": f"网络请求失败: {e}"}
        except Exception as e:
            return False, {"error": f"解密失败: {type(e).__name__}: {e}"}
        if obj.get("__plain__"):
            return False, {"error": "服务端返回明文(未加密)", "raw": obj["obj"]}
        code = obj.get("errorCode")
        if code == 2002 and not retried:
            # 会话过期 → 同 deviceId 刷新游客 token 后重试一次
            print(f"[acct] {path} 会话过期(2002)，自动刷新游客账号…", flush=True)
            ok, info = create_guest()
            if not ok:
                return False, {"error": "会话过期且刷新失败", "detail": info}
            payload["token"] = CFG["token"]
            retried = True
            continue
        if obj.get("status") != "y":
            return False, {"error": f"接口返回 status={obj.get('status')} errorCode={code}",
                           "msg": obj.get("msg", ""), "obj": obj}
        return True, obj


# ---------------------------------------------------------------- m3u8 代理
def rewrite_m3u8(text: str) -> str:
    """把 m3u8 里的绝对 URL（分片/密钥）全部改写成走本机代理"""
    out = []
    for ln in text.splitlines():
        s = ln.strip()
        if s.startswith("#"):
            m = re.search(r'URI="([^"]+)"', s)
            if m and m.group(1).startswith("http"):
                s = s.replace(m.group(1), "/proxy/u?url=" + quote(m.group(1), safe=""))
            out.append(s)
        elif s.startswith("http://") or s.startswith("https://"):
            out.append("/proxy/u?url=" + quote(s, safe=""))
        else:
            out.append(ln)
    return "\n".join(out) + "\n"


def upstream_get(url: str, timeout=20):
    return requests.get(url, headers={
        "user-agent": PLAYER_UA,
        "referer": PLAYER_REFERER,
        "accept-encoding": "identity",   # 分片不要 gzip，原样透传
    }, stream=True, timeout=timeout)


# ---------------------------------------------------------------- Flask
app = Flask(__name__)


@app.get("/")
def index():
    html = os.path.join(BASE_DIR, "tx_player.html")
    if os.path.exists(html):
        return open(html, encoding="utf-8").read()
    return "tx_player.html 缺失", 404


@app.get("/play")
def play_page():
    """独立播放页（新窗口打开）：视频全程直链，不经过本服务器"""
    html = os.path.join(BASE_DIR, "play.html")
    if os.path.exists(html):
        return open(html, encoding="utf-8").read()
    return "play.html 缺失", 404


@app.get("/api/config")
def api_config():
    t = CFG["token"]
    return jsonify({"token": t, "device_id": CFG["device_id"], "api_host": CFG["api_host"],
                    "uid": t.rsplit("_", 1)[-1] if "_" in t else ""})


@app.post("/api/config")
def api_set_config():
    global CFG
    d = request.get_json(force=True, silent=True) or {}
    for k in ("device_id", "api_host"):
        if d.get(k):
            CFG[k] = d[k].strip()
    # token 允许留空 = 自动游客号
    if "token" in d:
        CFG["token"] = (d.get("token") or "").strip()
    if not CFG.get("token") and d.get("_auto_guest"):
        ok, info = create_guest()
        if not ok:
            return jsonify({"ok": False, "error": info})
    save_config(CFG)
    return jsonify({"ok": True})


@app.post("/api/newguest")
def api_newguest():
    """一键新建游客账号（换新 deviceId）"""
    ok, info = create_guest(force_new_device=True)
    if not ok:
        return jsonify({"ok": False, "error": info})
    return jsonify({"ok": True, **info})


@app.get("/api/userinfo")
def api_userinfo():
    ok, obj = api_post("/cxapi/user/info", {})
    if not ok:
        return jsonify({"ok": False, **obj})
    d = obj.get("data", {})
    return jsonify({"ok": True, "uid": d.get("id"), "username": d.get("username"),
                    "nickname": d.get("nickname"), "is_vip": d.get("is_vip"),
                    "vip_expire": d.get("vip_expire") or d.get("expire_time") or ""})


# ---------------------------------------------------------------- 分类（抓包中出现过的全部 position）
POSITIONS = [
    ("app_home_tj",  "推荐"),
    ("app_home_new", "最新"),
    ("app_home_rm",  "热门"),
    ("app_home_gc",  "国产"),
    ("app_home_yc",  "原创"),
    ("app_home_zz",  "自制"),
    ("app_home_wh",  "网红"),
    ("app_home_ll",  "伦理"),
    ("app_home_av",  "AV"),
    ("app_home_dm",  "动漫"),
    ("app_dark_tj",  "暗黑推荐"),
]


def card(it: dict) -> dict:
    return {
        "id": it.get("id"), "name": it.get("name"), "img": it.get("img"),
        "nickname": it.get("nickname"), "click": it.get("click"),
        "duration": it.get("duration", ""), "pay_type": it.get("pay_type", ""),
        "money": it.get("money", ""),
    }


@app.get("/api/positions")
def api_positions():
    return jsonify({"ok": True, "positions": [{"key": k, "label": v} for k, v in POSITIONS]})


@app.post("/api/block")
def api_block():
    """分类/首页区块流：POST {position, page}"""
    d = request.get_json(force=True, silent=True) or {}
    position = d.get("position") or POSITIONS[0][0]
    if position not in [k for k, _ in POSITIONS]:
        return jsonify({"ok": False, "error": "未知分类"})
    ok, obj = api_post("/cxapi/movie/block", {"page": int(d.get("page", 1)), "position": position})
    if not ok:
        return jsonify({"ok": False, **obj})
    sections = []
    for b in (obj.get("data") or []):
        if not isinstance(b, dict):
            continue
        items = [card(it) for it in (b.get("items") or []) if isinstance(it, dict) and it.get("id")]
        if items:
            sections.append({"name": (b.get("name") or "").strip(), "style": b.get("style"), "items": items})
    return jsonify({"ok": True, "position": position, "page": d.get("page", 1), "sections": sections})


@app.post("/api/search")
def api_search():
    d = request.get_json(force=True, silent=True) or {}
    page = int(d.get("page", 1))
    q = (d.get("q") or "").strip()
    data = {"page": page, "page_size": "24", "order": "rand", "ad_code": "app_video_list"}
    if q:
        data["keywords"] = q          # 关键词搜索（抓包里只有首页推荐流，此参数未验证）
    ok, obj = api_post("/cxapi/movie/search", data)
    if not ok:
        return jsonify({"ok": False, **obj})
    lst = obj.get("data") or []
    items = [card(it) for it in lst if isinstance(it, dict) and it.get("id")]
    return jsonify({"ok": True, "items": items, "page": page})


@app.post("/api/detail")
def api_detail():
    d = request.get_json(force=True, silent=True) or {}
    vid = str(d.get("id", "")).strip()
    if not vid:
        return jsonify({"ok": False, "error": "缺少 id"})
    ok, obj = api_post("/cxapi/movie/detail", {"id": vid})
    if not ok:
        return jsonify({"ok": False, **obj})
    v = obj.get("data", {})
    return jsonify({
        "ok": True,
        "id": v.get("id"), "name": v.get("name"), "img": v.get("img"),
        "nickname": v.get("nickname"), "duration": v.get("duration"),
        "click": v.get("click"), "love": v.get("love"), "score": v.get("score"),
        "cat_name": v.get("cat_name"), "tags": [t.get("name") for t in (v.get("tags") or []) if isinstance(t, dict)],
        "play_link": v.get("play_link"), "pay_type": v.get("pay_type"),
        "money": v.get("money"), "layer_type": v.get("layer_type"), "play_tips": v.get("play_tips"),
        "proxy_url": ("/proxy/m3u8?url=" + quote(v["play_link"], safe="")) if v.get("play_link") else "",
    })


IMG_MAGIC_DEBUG = os.path.join(BASE_DIR, "img_debug")
_img_dump_count = [0]
_img_cache = {}   # url -> (mime, bytes)，简单内存缓存


def sniff_image(data: bytes):
    if data[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if data[:4] == b"GIF8":
        return "image/gif"
    if len(data) > 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    if len(data) > 12 and data[4:8] == b"ftyp":
        return "image/heic"      # ISO-BMFF 容器：可能是 AVIF（浏览器可解码）或 HEIC（需转换）
    return None


# HEIC/HEIF → JPEG 转换（Chrome 不支持 HEIC，需服务端转码）
try:
    import io
    import pillow_heif
    from PIL import Image, ImageOps
    pillow_heif.register_heif_opener()
    _HEIF_OK = True
except Exception:
    _HEIF_OK = False


def heic_brand(data: bytes) -> str:
    return data[8:12].decode("ascii", "replace") if len(data) > 12 else "?"


def heic_to_jpeg(data: bytes) -> bytes:
    img = ImageOps.exif_transpose(Image.open(io.BytesIO(data)))
    if img.mode not in ("RGB", "L"):
        img = img.convert("RGB")
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=88)
    return buf.getvalue()


_heic_conv_count = [0]


def _log_heic_convert(brand: str, size: int):
    """统计 HEIC→JPEG 转换是否真的发生过（用于评估 pillow-heif 依赖是否必要）"""
    _heic_conv_count[0] += 1
    line = f"{time.strftime('%m-%d %H:%M:%S')} | #{_heic_conv_count[0]} brand={brand} {size}B"
    print(f"[img] HEIC已转换为JPEG {line}", flush=True)
    try:
        os.makedirs(IMG_MAGIC_DEBUG, exist_ok=True)
        with open(os.path.join(IMG_MAGIC_DEBUG, "heic_convert.log"), "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def finalize(data: bytes):
    """返回 (bytes, mime)；HEIC 自动转 JPEG；非图片返回 (None, None)"""
    mime = sniff_image(data)
    if mime is None:
        return None, None
    if mime == "image/heic":
        brand = heic_brand(data)
        if brand in ("avif", "avis"):
            return data, "image/avif"       # Chrome 原生支持 AVIF
        if not _HEIF_OK:
            print(f"[img] HEIC({brand}) 但缺少 pillow-heif，无法转换", flush=True)
            return None, None
        try:
            jpg = heic_to_jpeg(data)
            _log_heic_convert(brand, len(data))
            return jpg, "image/jpeg"
        except Exception as e:
            print(f"[img] HEIC({brand}) 转换失败: {type(e).__name__}: {e}", flush=True)
            return None, None
    return data, mime


def decode_bnc(data: bytes):
    """App 内 .bnc 图片为 AES-ECB 加密（blutter: EnDecodeUtil::decrypt, AESMode=ECB, 零IV, PKCS7）。
    密钥 img_key 由 /cxapi/system/info 下发、global_logic 存入全局静态字段。"""
    if not data or len(data) % 16:
        return None, None
    keys = [CFG.get("img_key", ""), "525202f9149e061d", "5dbe9443aa4d2e4a"]
    for k in keys:
        if not k or len(k.encode()) not in (16, 24, 32):
            continue
        raw = AES.new(k.encode(), AES.MODE_ECB).decrypt(data)
        for cand in (raw, ):
            pt, mime = finalize(cand)
            if pt:
                return pt, mime
        try:
            pt, mime = finalize(unpad(raw, 16))
            if pt:
                return pt, mime
        except ValueError:
            pass
    return None, None


def refresh_img_key():
    """解密失败时重新拉 system/info 刷新 img_key（服务端可能轮换）"""
    ok, obj = api_post("/cxapi/system/info", {})
    if ok:
        k = (obj.get("data") or {}).get("img_key")
        if k and k != CFG.get("img_key"):
            CFG["img_key"] = k
            save_config(CFG)
            print(f"[img] img_key 已刷新: {k}", flush=True)
            return True
    return False


from urllib.parse import quote, unquote


def normalize_img_url(u: str):
    """接口返回的 img 可能自带百分号编码（甚至多重），迭代解码到稳定为止。
    返回 (归一化URL, 是否发生过解码)"""
    cur = u
    for _ in range(4):
        dec = unquote(cur)
        if dec == cur:
            break
        cur = dec
    return cur, cur != u


@app.get("/proxy/img")
def proxy_img():
    """封面图代理：.bnc 为 AES-ECB 加密图片，先解密再回传；失败样本与原因记录到 img_debug/"""
    global _img_dump_count
    url_raw = request.query_string.decode("utf-8", "replace")
    url = request.args.get("url", "")
    if not url.startswith("http"):
        return "bad url", 400
    # 归一化：处理接口数据里自带的 %xx 编码（多重编码也能还原）
    norm, changed = normalize_img_url(url)
    if changed:
        print(f"[img] URL已归一化:\n  原始: {url!r}\n  归一: {norm!r}", flush=True)
        url = norm
    cache_key = url
    if cache_key in _img_cache:
        mime, body = _img_cache[cache_key]
        return Response(body, mimetype=mime, headers={"Cache-Control": "public, max-age=86400"})

    def log_fail(reason):
        try:
            os.makedirs(IMG_MAGIC_DEBUG, exist_ok=True)
            with open(os.path.join(IMG_MAGIC_DEBUG, "failures.log"), "a", encoding="utf-8") as f:
                f.write(f"{time.strftime('%H:%M:%S')} | {reason} | {url!r}\n")
        except Exception:
            pass
        print(f"[img] {reason}: {url[:120]}", flush=True)

    def remember(mime, body):
        if len(_img_cache) > 500:
            _img_cache.clear()
        _img_cache[cache_key] = (mime, body)

    attempts = [
        {"user-agent": DART_UA},
        {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
         "referer": CFG["api_host"] + "/"},
        {"user-agent": PLAYER_UA, "referer": PLAYER_REFERER},
    ]
    last_data, last_reason = b"", "no attempt"
    for h in attempts:
        try:
            r = requests.get(url, headers=h, timeout=12)
        except Exception as e:
            last_reason = f"网络错误 {type(e).__name__}"
            continue
        if r.status_code != 200 or not r.content:
            last_reason = f"HTTP {r.status_code}, len={len(r.content)}"
            continue
        data = r.content
        body, mime = finalize(data)
        if body:
            remember(mime, body)
            return Response(body, mimetype=mime, headers={"Cache-Control": "public, max-age=86400"})
        # 不是明文图片 → 尝试 .bnc AES 解密（长度不对齐时截齐再试）
        cands = [data]
        if len(data) % 16:
            cands.append(data[: len(data) // 16 * 16])
        for c in cands:
            pt, mime2 = decode_bnc(c)
            if not pt and refresh_img_key():
                pt, mime2 = decode_bnc(c)
            if pt:
                remember(mime2 or "image/jpeg", pt)
                return Response(pt, mimetype=mime2 or "image/jpeg",
                                headers={"Cache-Control": "public, max-age=86400"})
        last_data, last_reason = data, f"解密失败 len={len(data)} len%16={len(data)%16}"
    # 全部失败：落盘前若干样本供分析
    if last_data and _img_dump_count[0] < 20:
        _img_dump_count[0] += 1
        try:
            os.makedirs(IMG_MAGIC_DEBUG, exist_ok=True)
            with open(os.path.join(IMG_MAGIC_DEBUG, f"fail_{_img_dump_count[0]}.bin"), "wb") as f:
                f.write(last_data)
            last_reason += f" 样本img_debug/fail_{_img_dump_count[0]}.bin"
        except Exception:
            pass
    log_fail(last_reason)
    return "img fail", 502


@app.get("/proxy/m3u8")
def proxy_m3u8():
    url = request.args.get("url", "")
    if not url.startswith("http"):
        return "bad url", 400
    try:
        r = upstream_get(url)
        text = r.content.decode("utf-8", "replace")
        return Response(rewrite_m3u8(text), mimetype="application/vnd.apple.mpegurl")
    except Exception as e:
        return f"m3u8 拉取失败: {e}", 502


@app.get("/proxy/u")
def proxy_segment():
    """代理 ts 分片 / AES-128 密钥（保留原签名参数）"""
    url = request.args.get("url", "")
    if not url.startswith("http"):
        return "bad url", 400
    try:
        r = upstream_get(url)
    except Exception as e:
        return f"拉流失败: {e}", 502
    headers = {}
    if r.headers.get("Content-Type"):
        headers["Content-Type"] = r.headers["Content-Type"]
    if r.headers.get("Content-Length"):
        headers["Content-Length"] = r.headers["Content-Length"]
    return Response(stream_with_context(r.iter_content(chunk_size=64 * 1024)),
                    status=r.status_code, headers=headers)


if __name__ == "__main__":
    import socket
    def lan_ip():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("223.5.5.5", 80)); return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"
        finally:
            s.close()
    host = CFG.get("listen_host", "0.0.0.0")   # 0.0.0.0 = 允许手机/内网穿透访问；改 127.0.0.1 则仅本机
    print("=" * 56)
    print("  本机访问    →  http://127.0.0.1:8071")
    if host == "0.0.0.0":
        print(f"  局域网访问  →  http://{lan_ip()}:8071   （手机/内网穿透用）")
    print("  账号配置文件:", CONFIG_PATH)
    print("=" * 56)
    if not CFG.get("token"):
        ok, info = create_guest()
        if not ok:
            print(f"[acct] {info}（将在首次请求时重试）", flush=True)
    app.run(host=host, port=8071, debug=False)
