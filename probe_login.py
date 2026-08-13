#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""探针: freessl 登录验证码形态测试"""
import json
import sys
from playwright.sync_api import sync_playwright

EMAIL = "475614239@qq.com"
PASSWORD = "nimabi11"

result = {"capclass": None, "subcapclass": None, "challenge": None, "ticket": None, "login_code": None}

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    ctx = browser.new_context(user_agent=(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"), locale="zh-CN")
    page = ctx.new_page()

    def on_response(resp):
        url = resp.url
        if "cap_union_prehandle" in url:
            try:
                body = resp.json()
                d = body.get("data", {})
                result["capclass"] = body.get("capclass")
                result["subcapclass"] = body.get("subcapclass")
                result["challenge"] = (d.get("dyn_show_info") or {}).get("instruction") or (
                    d.get("drag_hint") or d.get("drag_show_info") or {}).get("instruction")
                if body.get("ticket"):
                    result["ticket"] = body["ticket"][:30] + "..."
            except Exception:
                pass
        if "/api/login" in url and "outLogin" not in url and resp.request.method == "POST":
            try:
                result["login_code"] = resp.json().get("code")
            except Exception:
                pass

    page.on("response", on_response)
    page.goto("https://freessl.cn/user/login", wait_until="domcontentloaded", timeout=60000)
    page.wait_for_timeout(2500)
    page.fill("input[name=email]", EMAIL)
    page.fill("input[name=password]", PASSWORD)
    page.wait_for_timeout(500)
    # 看看页面是否出现验证码容器
    has_cap = page.eval_on_selector_all(".tcaptcha-transform, #tcaptcha_transform, .tencent-captcha", "els => els.length")
    page.query_selector("button[type=submit], .ant-btn-primary").click()
    page.wait_for_timeout(6000)

    print(json.dumps(result, ensure_ascii=False, indent=2))
    html = page.content()
    if "tcaptcha" in html or "captcha" in html.lower():
        print("页面含 captcha 元素: TRUE")
    browser.close()