#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
captcha_solver.py — freessl 腾讯验证码自动识别登录
用法: python3 captcha_solver.py
"""
import argparse
import base64
import io
import json
import os
import random
import re
import time
import urllib.request

# venv 内置浏览器路径
_venv_browsers = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               ".venv", "ms-playwright")
if os.path.isdir(_venv_browsers):
    os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", _venv_browsers)

import sys
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

from PIL import Image
from playwright.sync_api import sync_playwright

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
CAP_DIR     = os.path.join(BASE_DIR, "captcha")
UA          = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
               "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36")
MAX_ROUNDS  = 3

PROMPT = """\
这是腾讯图标点选验证码，共两张图：
图1（指令条）：从左到右排列 2-4 个目标字符或图标，代表点击顺序。
图2（挑战图，坐标系 672x480）：AI 生成背景上散布多个带圆形边框的图标标记，含干扰项。

请完成以下任务：
① 读出图1字符/图标序列原文（targets）
② 在图2找到匹配标记，按图1顺序记录各标记圆心坐标
③ 仅输出 JSON，不加任何其他文字：
{"targets":"图1原文","clicks":[{"x":整数,"y":整数},…]}

约束：clicks 数量 == targets 字符数；x∈[0,672]，y∈[0,480]；坐标精确到圆心像素。"""


# ── 配置读写 ───────────────────────────────────────────────────────────────────

def load_cfg() -> dict:
    return json.load(open(CONFIG_FILE, encoding="utf-8"))


def save_cfg(cfg: dict) -> None:
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


# ── 工具函数 ───────────────────────────────────────────────────────────────────

def parse_proxy(proxy_url: str):
    """解析 http://user:pass@host:port -> Playwright proxy 格式"""
    if not proxy_url:
        return None
    m = re.match(r'^(https?://)(?:([^:]+):([^@]+)@)?(.+)$', proxy_url.strip())
    if m:
        scheme, user, pwd, host = m.groups()
        p = {"server": f"{scheme}{host}"}
        if user and pwd:
            p["username"] = user
            p["password"] = pwd
        return p
    return {"server": proxy_url}


def encode_img(path: str) -> str:
    return base64.b64encode(open(path, "rb").read()).decode()


def scale_png(src: str, factor: int = 3) -> str:
    """放大图片 factor 倍保存，返回新路径。用于提升 Gemini 对小图的识别率。"""
    im  = Image.open(src)
    dst = src.replace(".png", f"_{factor}x.png")
    im.resize((im.width * factor, im.height * factor), Image.LANCZOS).save(dst)
    return dst


def parse_json(text: str) -> dict:
    """容错解析模型返回的 JSON：剥 markdown 围栏 → 截取 {...} → 正则回退。"""
    t = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip(), flags=re.I | re.M)
    s, e = t.find("{"), t.rfind("}")
    if s != -1 and e > s:
        t = t[s:e + 1]
    try:
        return json.loads(t)
    except json.JSONDecodeError:
        # 正则回退：处理 Gemini 偶发的 JSON 格式错误
        tm = re.search(r'"targets"\s*:\s*"([^"]*)"', t)
        cm = re.findall(r'"x"\s*:\s*(\d+)[^}]*?"y"\s*:\s*(\d+)', t)
        if tm and cm:
            return {"targets": tm.group(1),
                    "clicks": [{"x": int(x), "y": int(y)} for x, y in cm]}
        raise


def in_bounds(pts: list) -> bool:
    return all(10 <= x <= 662 and 10 <= y <= 470 for x, y in pts)


def capture_image(resp, captured: dict) -> None:
    """Playwright response 回调：拦截并缓存验证码图片。"""
    if "cap_union_new_getcapbysig" not in resp.url:
        return
    try:
        body = resp.body()
        im   = Image.open(io.BytesIO(body))
        captured.setdefault(im.size, body)
    except Exception:
        pass


# ── Gemini 识别 ────────────────────────────────────────────────────────────────

def gemini_solve(cfg: dict, bg_path: str, strip_path: str, timeout: int = 55):
    """
    调用 Gemini 识别验证码。
    - 指令条放大 3 倍再发送，提升小图识别率
    - 每个 key 最多重试 2 次，遇 429 限流立即换下一个 key
    返回 (targets_str, [(x,y),...]) 或 (None, None)
    """
    keys  = cfg.get("gemini_api_keys") or (
            [cfg["gemini_api_key"]] if cfg.get("gemini_api_key") else [])
    model = cfg.get("gemini_model", "gemini-2.0-flash")
    if not keys:
        return None, None

    big_strip = scale_png(strip_path, factor=3)   # 放大指令条
    body = json.dumps({
        "contents": [{"parts": [
            {"text": PROMPT},
            {"inline_data": {"mime_type": "image/png", "data": encode_img(big_strip)}},
            {"inline_data": {"mime_type": "image/png", "data": encode_img(bg_path)}},
        ]}],
        "generationConfig": {"response_mime_type": "application/json", "temperature": 0},
    }).encode()

    for ki, key in enumerate(keys, 1):
        url = (f"https://generativelanguage.googleapis.com/v1beta/"
               f"models/{model}:generateContent")
        req = urllib.request.Request(
            url, data=body,
            headers={"Content-Type": "application/json", "x-goog-api-key": key},
            method="POST",
        )
        for attempt in range(1, 3):
            try:
                print(f"   [Gemini] key{ki}/{len(keys)} {model} 第{attempt}次...")
                proxy_url = cfg.get("proxy")
                handlers = [urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})] if proxy_url else []
                opener = urllib.request.build_opener(*handlers)
                with opener.open(req, timeout=timeout) as r:
                    resp    = json.loads(r.read().decode())
                text        = resp["candidates"][0]["content"]["parts"][0]["text"]
                data        = parse_json(text)
                targets     = str(data.get("targets", "")).strip()
                clicks      = [(int(c["x"]), int(c["y"])) for c in data.get("clicks", [])]
                print(f"   [Gemini] targets={targets!r}  clicks={clicks}")
                if targets and clicks:
                    return targets, clicks
            except Exception as e:
                msg = str(e)[:120]
                print(f"   [Gemini] key{ki} 第{attempt}次失败: {msg}")
                if "429" in msg:
                    break           # 该 key 限流，换下一个
                if attempt == 1:
                    time.sleep(5)   # 短暂等待后重试

    return None, None


# ── 点击逻辑 ───────────────────────────────────────────────────────────────────

def click_targets(page, pts: list, bg_box: dict, scale: float) -> None:
    """按坐标依次点击，并在页面叠加红圈标注（便于调试）。"""
    print(f"==> 依次点击 {len(pts)} 个目标")
    for i, (x, y) in enumerate(pts, 1):
        sx, sy = bg_box["x"] + x * scale, bg_box["y"] + y * scale
        try:
            page.evaluate("""([px, py]) => {
                const d = document.createElement('div');
                d.style.cssText = `position:fixed;left:${px-10}px;top:${py-10}px;` +
                    `width:20px;height:20px;border:3px solid red;border-radius:50%;` +
                    `z-index:99999;pointer-events:none;`;
                d.setAttribute('data-mark', '1');
                document.body.appendChild(d);
            }""", [sx, sy])
        except Exception:
            pass
        page.mouse.move(sx, sy)
        page.wait_for_timeout(random.randint(100, 220))
        page.mouse.click(sx, sy)
        print(f"   [{i}] 图({x:.0f},{y:.0f}) → 页面({sx:.1f},{sy:.1f})")
        page.wait_for_timeout(random.randint(250, 450))
    try:
        page.evaluate("() => document.querySelectorAll('[data-mark]').forEach(e=>e.remove())")
    except Exception:
        pass


# ── 单轮完整流程 ───────────────────────────────────────────────────────────────

def run_round(page, cfg: dict, captured: dict, login: dict) -> bool:
    """
    执行一轮：登录表单 → 等验证码 → 抓图 → Gemini识别 → 点击 → 等结果。
    返回 True 表示需要重试，False 表示已完成（成功或无需继续）。
    """
    t0      = time.time()
    TIMEOUT = 60

    def left() -> float:
        return TIMEOUT - (time.time() - t0)

    def ms(sec) -> int:
        return int(sec * 1000)

    # ── 提交登录表单 ───────────────────────────────────────────────────────────
    print("==> 打开 freessl 登录页")
    page.goto("https://freessl.cn/user/login", wait_until="domcontentloaded", timeout=60000)
    page.wait_for_timeout(1200)
    page.evaluate("""() => {
        for (const b of document.querySelectorAll('.ant-modal-content button'))
            if (b.innerText.includes('已知')) { b.click(); return; }
        document.querySelector('.ant-modal-wrap')?.remove();
    }""")
    page.wait_for_timeout(400)
    page.fill("#basic_email",    cfg.get("email", ""))
    page.fill("#basic_password", cfg.get("freessl_password") or cfg.get("password", ""))
    page.click("button[type=submit]")

    # ── 等待验证码弹出 ─────────────────────────────────────────────────────────
    print("==> 等待验证码")
    tcap = None
    for _ in range(30):
        if left() <= 0:
            break
        page.wait_for_timeout(min(1000, max(200, ms(left()))))
        if page.locator("#tcaptcha_transform_dy").count():
            tcap = page.locator("#tcaptcha_transform_dy")
            break
        if login.get("code") == 0:
            return False    # 直接免验证码登录成功

    if tcap is None:
        print("!! 未出现验证码")
        return True

    # ── 等图片加载（最多重试4次，失败时点刷新） ────────────────────────────────
    big = small = None
    for _ in range(4):
        for size, body in list(captured.items()):
            if size == (672, 480):   big   = body
            elif size == (170, 50):  small = body
        if big and small:
            break
        if left() <= 0:
            break
        for sel in ("[class*='refresh']", "[class*='Refresh']", "[aria-label*='刷新']"):
            try:
                loc = tcap.locator(sel).first
                if loc.count():
                    loc.click(timeout=1500, force=True)
                    break
            except Exception:
                pass
        captured.clear()
        page.wait_for_timeout(min(3000, max(300, ms(left()))))

    if not big or not small:
        print("!! 验证码图片抓取失败")
        return True

    # ── 保存图片 ──────────────────────────────────────────────────────────────
    ts         = time.strftime("%m%d_%H%M%S")
    bg_path    = os.path.join(CAP_DIR, f"cap_bg_{ts}.png")
    strip_path = os.path.join(CAP_DIR, f"cap_instr_{ts}.png")
    open(bg_path,    "wb").write(big)
    open(strip_path, "wb").write(small)

    # ── 定位挑战区，计算缩放比 ────────────────────────────────────────────────
    bg_box = tcap.locator(".tencent-captcha-dy__image-area").first.bounding_box()
    if not bg_box:
        print("!! 挑战区定位失败")
        return True
    scale = bg_box["width"] / 672.0
    print(f"   挑战区: ({bg_box['x']:.0f},{bg_box['y']:.0f}) "
          f"{bg_box['width']:.0f}×{bg_box['height']:.0f}  "
          f"scale={scale:.4f}  剩余={left():.0f}s")

    # ── Gemini 识别 ──────────────────────────────────────────────────────────
    targets, pts = None, None
    if left() > 8:
        targets, pts = gemini_solve(cfg, bg_path, strip_path,
                                    timeout=max(5, int(left()) - 4))
    else:
        print("   剩余时间不足，跳过识别")

    if pts and not in_bounds(pts):
        print("   坐标越界，弃用")
        pts = None

    if not pts:
        return True     # 无有效坐标，重试

    # ── 点击目标 + 点击确定 ───────────────────────────────────────────────────
    click_targets(page, pts, bg_box, scale)

    print("==> 点击 [确定]")
    try:
        tcap.locator("button:has-text('确定'), [class*='confirm']").first.click(timeout=5000)
        print("   [确定] 已点击")
    except Exception:
        print("   [确定] 按钮未找到")

    page.wait_for_timeout(2500)
    try:
        st = tcap.inner_text(timeout=2000)[:160].replace("\n", " | ")
        print(f"   容器状态: {st}")
    except Exception:
        pass

    # ── 等待登录结果 ──────────────────────────────────────────────────────────
    print("==> 等待登录结果")
    while left() > 2:
        if login.get("code") is not None:
            break
        page.wait_for_timeout(min(2000, max(300, ms(left()))))
        new_bigs = [b for s, b in captured.items() if s == (672, 480)]
        if new_bigs and new_bigs[-1] is not big:
            print("   验证码已刷新（点错），重试")
            return True

    code = login.get("code")
    if code == 0:
        return False
    if code is not None:
        print(f"   登录接口返回 code={code}: {str(login.get('msg'))[:60]}")
    if left() <= 2:
        print("   60s 时间箱耗尽，重试")
    return True


# ── 主入口 ─────────────────────────────────────────────────────────────────────

def solve_login(cfg: dict = None, max_rounds: int = MAX_ROUNDS, headless: bool = None) -> bool:
    """
    登录 freessl 并自动把新 SESSION_ID 写回 config.json。
    - 可由 autossl.py 联动调用(凭证失效时自动刷新)
    - 独立运行: python3 captcha_solver.py [--headless]
    返回 True=登录成功(已写回config), False=失败
    """
    cfg      = cfg or load_cfg()
    if headless is None:
        # 青龙/Linux 无显示器默认 headless; macOS 弹有头窗口便于人工兜底
        headless = (sys.platform != "darwin") and not os.environ.get("DISPLAY")
    os.makedirs(CAP_DIR, exist_ok=True)
    login    = {}
    captured = {}

    with sync_playwright() as p:
        launch_kwargs = {"headless": headless}
        pw_proxy = parse_proxy(cfg.get("proxy"))
        if pw_proxy:
            launch_kwargs["proxy"] = pw_proxy
        browser = p.chromium.launch(**launch_kwargs)
        ctx     = browser.new_context(
            user_agent=UA, locale="zh-CN",
            viewport={"width": 1280, "height": 900},
        )

        def on_login(resp):
            if "/api/login" in resp.url and resp.request.method == "POST" \
                    and "outLogin" not in resp.url:
                try:
                    j = resp.json()
                    login.update(code=j.get("code"), msg=j.get("msg"))
                    if j.get("code") == 0:
                        fresh = [c for c in ctx.cookies()
                                 if c["name"] in ("SESSION_ID", "TDC_itoken", "lang")]
                        cfg2  = load_cfg()
                        cfg2["freessl_cookie"] = "; ".join(
                            f"{c['name']}={c['value']}" for c in fresh)
                        save_cfg(cfg2)
                        print("  => SESSION_ID 已写回 config.json")
                except Exception:
                    pass

        for attempt in range(1, max_rounds + 1):
            print(f"\n========== 第 {attempt}/{max_rounds} 轮 ==========")
            login.clear()       # 清除上轮状态，避免影响本轮判断
            captured.clear()

            page = ctx.new_page()
            page.on("response", on_login)
            page.on("response", lambda resp: capture_image(resp, captured))

            should_retry = run_round(page, cfg, captured, login)
            try:
                page.close()
            except Exception:
                pass

            if not should_retry or login.get("code") == 0:
                break

        if login.get("code") == 0:
            print("\n=== 登录成功! SESSION_ID 已写回 config.json ===")
        else:
            print(f"\n=== {max_rounds} 次尝试均未成功 ===")
            print("    可重新运行本工具；若持续失败请人工登录更新 Cookie")

        browser.close()

    return login.get("code") == 0


def main():
    ap = argparse.ArgumentParser(description="freessl 验证码自动登录, 刷新 SESSION_ID")
    ap.add_argument("--headless", action="store_true",
                    help="无头模式(青龙/无显示器环境)")
    ap.add_argument("--rounds", type=int, default=MAX_ROUNDS,
                    help="重试轮数(默认3)")
    args = ap.parse_args()
    ok = solve_login(max_rounds=args.rounds, headless=args.headless or None)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
