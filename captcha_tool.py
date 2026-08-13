#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
captcha_tool.py — freessl 登录验证码人工协作工具
流程:
  1. 有头浏览器自动登录 freessl, 触发腾讯验证码窗口
  2. 输出验证码窗口几何信息 + 保存:
       - captcha/captcha_<ts>_page.png   整页截图(含验证码窗口)
       - captcha/captcha_<ts>_bg.png     验证码背景原图(672x480, 供Gemini标注坐标)
  3. 点击探测: 在背景图中心点击, 验证事件捕获与 iframe 坐标映射
  4. 等待 Gemini 坐标 (写入 captcha/coords.txt 或终端粘贴, 图片坐标, 按点击顺序)
  5. 按坐标点击 -> 验证码通过 -> 页面自动登录 -> 新 SESSION_ID 写回 config.json
用法:
  python3 captcha_tool.py
"""
import io
import json
import os
import random
import re
import select
import sys
import time
import urllib.request

from playwright.sync_api import sync_playwright

from PIL import Image

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
CAP_DIR = os.path.join(BASE_DIR, "captcha")
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36")


def load_cfg():
    if not os.path.exists(CONFIG_FILE):
        sys.exit("缺少 config.json")
    return json.load(open(CONFIG_FILE, encoding="utf-8"))


def save_cfg(cfg):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


def find_captcha_frame(page):
    """找包含验证码背景图的 iframe (优先), 其次 turing.captcha 域名 frame"""
    for fr in page.frames:
        try:
            if fr.locator("img[src*='getcapbysig']").count() > 0:
                return fr
        except Exception:
            pass
    for fr in page.frames:
        if "turing" in (fr.url or "") and "captcha" in (fr.url or ""):
            return fr
    return None


def frame_page_offset(page, frame):
    """计算 frame 左上角在主页面坐标系中的偏移"""
    x = y = 0.0
    cur = frame
    seen = 0
    while cur is not None and cur is not page.main_frame and cur.parent_frame is not None and seen < 10:
        try:
            box = cur.frame_element().bounding_box()
            if box:
                x += box["x"]
                y += box["y"]
        except Exception:
            pass
        cur = cur.parent_frame
        seen += 1
    return x, y


def find_bg_element(frame):
    """返回背景图元素(显示区域)"""
    for sel in ["img[src*='getcapbysig']", "[style*='getcapbysig']", "[data-url*='getcapbysig']"]:
        loc = frame.locator(sel).first
        try:
            if loc.count():
                box = loc.bounding_box()
                if box:
                    return loc, box
        except Exception:
            pass
    return None, None


def bg_image_url(el, frame):
    src = el.get_attribute("src") or ""
    if "getcapbysig" in src:
        return src if src.startswith("http") else "https://turing.captcha.qcloud.com" + src
    style = el.get_attribute("style") or ""
    for m in re.finditer(r"url\([\\'\"]?([^\\'\")]+)", style):
        u = m.group(1)
        if "getcapbysig" in u:
            return u if u.startswith("http") else "https://turing.captcha.qcloud.com" + u
    return None


def download(url, path):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA,
                                                   "Referer": "https://turing.captcha.qcloud.com/"})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = r.read()
        with open(path, "wb") as f:
            f.write(data)
        return data
    except Exception as e:
        print("  下载失败:", e)
        return None


def ask_coords():
    coords_path = os.path.join(CAP_DIR, "coords.txt")
    if os.path.exists(coords_path):
        os.remove(coords_path)
    deadline = time.time() + 600
    while time.time() < deadline:
        if os.path.exists(coords_path):
            txt = open(coords_path, encoding="utf-8").read().strip()
            if txt:
                return txt
        try:
            if sys.stdin in select.select([sys.stdin], [], [], 2)[0]:
                line = sys.stdin.readline().strip()
                if line:
                    return line
        except Exception:
            return None
    return None


def parse_coords(text):
    pts = []
    for pair in re.split(r"[\s;，；]+", text.strip()):
        m = re.match(r"^(\d+(?:\.\d+)?)\s*[,xX:：]\s*(\d+(?:\.\d+)?)$", pair)
        if m:
            pts.append((float(m.group(1)), float(m.group(2))))
    return pts


def main():
    os.makedirs(CAP_DIR, exist_ok=True)
    cfg = load_cfg()
    email = cfg.get("email")
    password = cfg.get("freessl_password")
    if not password:
        sys.exit("config.json 需增加 freessl_password 字段 (账号密码登录用)")
    ts = time.strftime("%Y%m%d_%H%M%S")
    login = {}   # /api/login 结果

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        ctx = browser.new_context(user_agent=UA, locale="zh-CN",
                                  viewport={"width": 1280, "height": 900})
        page = ctx.new_page()

        def on_login(resp):
            if "/api/login" in resp.url and resp.request.method == "POST" and "outLogin" not in resp.url:
                try:
                    j = resp.json()
                    login["code"] = j.get("code")
                    login["msg"] = j.get("msg")
                    if j.get("code") == 0:
                        cookies = ctx.cookies()
                        sid = next((c for c in cookies if c["name"] == "SESSION_ID"), None)
                        if sid:
                            c = load_cfg()
                            fresh = sorted(c for c in cookies if c["name"] in
                                           ("SESSION_ID", "TDC_itoken", "lang"))
                            c["freessl_cookie"] = "; ".join("%s=%s" % (x["name"], x["value"]) for x in fresh)
                            save_cfg(c)
                            print("  => 新 SESSION_ID 已写回 config.json")
                        else:
                            print("  !! 登录成功但未取到 SESSION_ID cookie")
                except Exception:
                    pass

        page.on("response", on_login)

        print("==> 打开登录页")
        page.goto("https://freessl.cn/user/login", wait_until="networkidle", timeout=60000)
        page.wait_for_timeout(1500)
        page.evaluate("""() => {
            const bts = document.querySelectorAll('.ant-modal-content button');
            for (const x of bts) if (x.innerText.includes('已知')) { x.click(); return; }
            const w = document.querySelector('.ant-modal-wrap'); if (w) w.remove();
        }""")
        page.wait_for_timeout(500)
        page.fill("#basic_email", email)
        page.fill("#basic_password", password)
        page.click("button[type=submit]")

        print("==> 等待验证码窗口 ...")
        cap = None
        for _ in range(25):
            page.wait_for_timeout(1000)
            cap = find_captcha_frame(page)
            if cap:
                break
            if login.get("code") == 0:
                print("无需验证码, 登录已成功")
                browser.close()
                return
        if not cap:
            print("!! 未出现验证码窗口, 截图已保存, 请查看 captcha/%s_page.png" % ts)
            page.screenshot(path=os.path.join(CAP_DIR, "captcha_%s_page.png" % ts))
            browser.close()
            return

        print("==> 验证码iframe:", cap.url[:110])
        off_x, off_y = frame_page_offset(page, cap)
        print("   iframe 页面偏移: (%.1f, %.1f)" % (off_x, off_y))

        bg_el, bg_box = find_bg_element(cap)
        if bg_el is None:
            print("!! 背景图未定位到, 整页截图已保存")
            page.screenshot(path=os.path.join(CAP_DIR, "captcha_%s_page.png" % ts))
            browser.close()
            return
        print("   背景图显示区(iframe内): x=%.1f y=%.1f w=%.1f h=%.1f" % (
            bg_box["x"], bg_box["y"], bg_box["width"], bg_box["height"]))

        bg_url = bg_image_url(bg_el, cap)
        nat = (672, 480)
        if bg_url:
            data = download(bg_url, os.path.join(CAP_DIR, "captcha_%s_bg.png" % ts))
            if data:
                nat = Image.open(io.BytesIO(data)).size
        scale = bg_box["width"] / nat[0]
        print("   背景图自然尺寸: %s  缩放比例: %.4f" % (nat, scale))

        page.screenshot(path=os.path.join(CAP_DIR, "captcha_%s_page.png" % ts))
        print("   截图已保存: captcha/captcha_%s_page.png(整页) 和 _bg.png(原图/Gemini用)" % ts)

        # ---- 点击探测: 中心点点击, 验证事件与映射 ----
        print("\n==> 探测: 点击背景图中心, 验证事件捕获与坐标映射")
        try:
            cap.evaluate("""() => {
                window.__clicks = [];
                document.addEventListener('click', function(e){
                    window.__clicks.push({x: e.clientX, y: e.clientY,
                        target: String(e.target.className || e.target.tagName || '').slice(0,60)});
                }, true);
            }""")
        except Exception as e:
            print("   监听安装失败:", e)
        cx = off_x + bg_box["x"] + bg_box["width"] / 2
        cy = off_y + bg_box["y"] + bg_box["height"] / 2
        page.mouse.click(cx, cy)
        page.wait_for_timeout(900)
        try:
            evs = cap.evaluate("window.__clicks || []")
            print("   收到点击事件 %d 个" % len(evs))
            for e in evs:
                print("     event@(%.0f, %.0f) target=%s" % (e["x"], e["y"], e["target"]))
            if evs and abs(evs[0]["x"] - bg_box["x"] - bg_box["width"] / 2) <= 3 and \
                    abs(evs[0]["y"] - bg_box["y"] - bg_box["height"] / 2) <= 3:
                print("   ✓ 坐标映射正确 — 页面坐标换算成功")
            else:
                print("   !! 坐标映射偏差大, 点击将可能落错位置")
        except Exception as e:
            print("   读取点击记录失败:", e)

        # ---- 等待坐标 ----
        print("\n==> 用 Gemini 分析 captcha/%s_bg.png, 得到标记坐标(图片像素), 按点击顺序排列" % ts)
        print("    格式如: 120,80 300,150 450,220")
        print("    写入 captcha/coords.txt 或直接粘贴到终端(等待最多10分钟)")
        text = ask_coords()
        if not text:
            print("!! 超时未提供坐标, 关闭浏览器")
            browser.close()
            return
        pts = parse_coords(text)
        if not pts:
            print("!! 坐标格式无法解析:", text)
            browser.close()
            return

        print("\n==> 依次点击 %d 个坐标" % len(pts))
        for i, (x, y) in enumerate(pts, 1):
            sx = off_x + bg_box["x"] + x * scale
            sy = off_y + bg_box["y"] + y * scale
            page.mouse.move(sx, sy)
            page.wait_for_timeout(random.randint(100, 300))
            page.mouse.click(sx, sy)
            print("   [%d] (%.0f,%.0f) -> 页面(%.0f,%.0f)" % (i, x, y, sx, sy))
            page.wait_for_timeout(random.randint(400, 900))

        print("==> 等待验证码校验并自动登录 (最多90s)")
        deadline = time.time() + 90
        while time.time() < deadline:
            if login.get("code") is not None:
                break
            page.wait_for_timeout(3000)

        if login.get("code") == 0:
            print("\n✓ 登录成功, SESSION_ID 已更新, 可运行 autossl.py")
        else:
            print("\n!! 登录结果: code=%s msg=%s" % (login.get("code"), login.get("msg")))
            print("   可能点错坐标验证码被刷新, 重新运行本工具对齐新图即可")
        page.screenshot(path=os.path.join(CAP_DIR, "captcha_%s_result.png" % ts))
        browser.close()


if __name__ == "__main__":
    main()