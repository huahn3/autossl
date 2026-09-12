#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
autossl.py — 自动化申请 SSL 证书
流程: csr.chinassl.net 生成CSR → freessl.cn 申请证书 → dashboard.passnat.com 填写DNS验证记录 → 触发验证 → 下载证书

用法:
    python3 autossl.py                    # 默认: 先检查已有证书, 到期<=30天或无证书才申请 (推荐, 青龙直接用)
    python3 autossl.py huhan3nd.odn.cc    # 只处理指定域名
    python3 autossl.py --always           # 跳过检查, 强制重新申请

输出目录: output/<域名>/
    domain.csr  证书签名请求
    domain.key  私钥
    domain.crt  证书
    cacert.pem  根/中间证书链
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")

UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36")

FREESSL_BASE = "https://freessl.cn"
PASSNAT_API = "https://api.passnat.com"


def passnat_headers(cfg):
    """passnat 认证: 优先用 API 密钥(sk_, 永不过期), 否则退回 cookie"""
    if cfg.get("passnat_token"):
        return {"Authorization": cfg["passnat_token"]}
    return {"Cookie": cfg.get("passnat_cookie", ""),
            "Origin": "https://dashboard.passnat.com",
            "Referer": "https://dashboard.passnat.com/"}
CSSL_BASE = "https://csr.chinassl.net"


class ApiError(Exception):
    pass


def log(msg):
    print(msg, flush=True)


_GLOBAL_PROXY = None

def set_global_proxy(proxy_url):
    global _GLOBAL_PROXY
    _GLOBAL_PROXY = proxy_url
    if proxy_url:
        os.environ["HTTP_PROXY"] = proxy_url
        os.environ["HTTPS_PROXY"] = proxy_url
        os.environ["http_proxy"] = proxy_url
        os.environ["https_proxy"] = proxy_url

def http(url, method="GET", data=None, cookies="", extra_headers=None, form=False, proxy=None):
    proxy = proxy or _GLOBAL_PROXY
    headers = {
        "User-Agent": UA,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    }
    if cookies:
        headers["Cookie"] = cookies
    if extra_headers:
        headers.update(extra_headers)
    body = None
    if data is not None:
        if form:
            body = urllib.parse.urlencode(data).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            body = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    opener = urllib.request.build_opener(*handlers)
    with opener.open(req, timeout=60) as resp:
        return resp.status, resp.read().decode("utf-8", "replace")


def parse_json(text, ctx):
    try:
        return json.loads(text)
    except ValueError:
        raise ApiError("[%s] 返回非JSON: %s" % (ctx, text[:400]))


def check_code(obj, ctx, ok_codes=(0, 10000)):
    if obj.get("code") not in ok_codes:
        raise ApiError("[%s] 业务错误 code=%s msg=%s" % (ctx, obj.get("code"), obj.get("msg") or obj.get("error")))
    return obj


# ---------------------------------------------------------------------------
# Step 1: csr.chinassl.net 生成 CSR + 私钥 (无需登录)
# ---------------------------------------------------------------------------
def gen_csr(csr_info, email, domain, keytype, keysize):
    log("==> [1/6] csr.chinassl.net 生成 CSR")
    data = {
        "company": csr_info["company"],
        "department": csr_info["department"],
        "city": csr_info["city"],
        "province": csr_info["province"],
        "country": csr_info["country"],
        "email": email,
        "domain": domain,
        "cryptography_algorithms": keytype,
        "hash_algorithms": "sha256",
        "keysize": keysize,
    }
    status, text = http(CSSL_BASE + "/generator-csr/generator-csr.php",
                        method="POST", data=data, form=True,
                        extra_headers={"Referer": CSSL_BASE + "/"})
    if status != 200:
        raise ApiError("[CSR生成] HTTP %s" % status)
    sep = "thisismyyahoohostspecialsplitstringhere"
    parts = text.split(sep)
    if len(parts) < 4:
        if "ERRORwrongcountry" in text:
            raise ApiError("[CSR生成] 国家代码非法")
        raise ApiError("[CSR生成] 响应格式异常: %s" % text[:400])
    csr, key = parts[0].strip(), parts[1].strip()
    if not csr.startswith("-----BEGIN") or not key.startswith("-----BEGIN"):
        raise ApiError("[CSR生成] 响应未包含CSR/KEY: %s" % text[:400])
    log("  CSR 和私钥已生成")
    return csr, key


# ---------------------------------------------------------------------------
# Step 2: freessl.cn 创建订单 (注意: 必须用表单编码, JSON 会报邮箱格式错误)
# ---------------------------------------------------------------------------
def freessl_create_order(cfg, domain):
    log("==> [2/6] freessl.cn 创建订单 (productid=%s)" % cfg["productid"])
    payload = {
        "email": cfg["email"],
        "authmethod": cfg["authmethod"],
        "productid": cfg["productid"],
        "csrfrom": "offline",
        "keytype": cfg["keytype"],
        "domains": domain,
        "csrpem": "",
        "from": "",
    }
    status, text = http(FREESSL_BASE + "/api/keymanager/order/create",
                        method="POST", data=payload, cookies=cfg["freessl_cookie"], form=True)
    obj = check_code(parse_json(text, "创建订单"), "创建订单")
    order_id = obj["msg"].get("order_id")
    if not order_id:
        raise ApiError("[创建订单] 响应缺少 order_id: %s" % text[:400])
    log("  order_id = %s" % order_id)
    return order_id


# ---------------------------------------------------------------------------
# Step 3: freessl.cn 提交 CSR (字段名是 csr, 表单编码)
# ---------------------------------------------------------------------------
def freessl_submit_csr(cfg, order_id, domain, csr):
    log("==> [3/6] freessl.cn 提交 CSR (order %s)" % order_id)
    payload = {
        "email": cfg["email"],
        "authmethod": cfg["authmethod"],
        "productid": cfg["productid"],
        "csrfrom": "user",
        "keytype": cfg["keytype"],
        "domains": domain,
        "csr": csr,
        "from": "",
        "ocspmuststaple": "false",
    }
    status, text = http(FREESSL_BASE + "/api/keymanager/order/csr/submit?id=" + str(order_id),
                        method="POST", data=payload, cookies=cfg["freessl_cookie"], form=True)
    obj = check_code(parse_json(text, "提交CSR"), "提交CSR")
    log("  CSR 提交成功: %s" % (obj.get("data") or "OK"))


# ---------------------------------------------------------------------------
# Step 4: freessl.cn commit 订单 → 返回 DNS 验证记录 (auth_info)
# ---------------------------------------------------------------------------
def freessl_commit(cfg, order_id):
    log("==> [4/6] freessl.cn 提交订单获取DNS验证记录 (commit)")
    status, text = http(FREESSL_BASE + "/api/keymanager/order/commit",
                        method="POST", data={"order_id": order_id},
                        cookies=cfg["freessl_cookie"], form=True)
    obj = check_code(parse_json(text, "commit"), "commit")
    msg = obj.get("msg") or {}
    auth_info = msg.get("auth_info") or []
    if not auth_info:
        raise ApiError("[commit] 响应无验证记录: %s" % text[:400])
    recs = []
    for a in auth_info:
        rec = {
            "record": a.get("auth_key") or a.get("auth_key_full"),   # 主机记录, 如 _dnsauth.huhan3nd
            "value": a.get("auth_value"),                            # 记录值 (TXT token)
            "auth_domain": a.get("auth_domain"),                     # 验证域名, 如 odn.cc
        }
        recs.append(rec)
        log("  验证记录: TXT %s.%s 值=%s" % (rec["record"], rec["auth_domain"], rec["value"]))
    return recs


# ---------------------------------------------------------------------------
# Step 5: api.passnat.com 填写验证记录 (5分钟有效)
# ---------------------------------------------------------------------------
def passnat_find_domain(cfg, full_domain):
    status, text = http(PASSNAT_API + "/user/domain/list", extra_headers=passnat_headers(cfg))
    obj = check_code(parse_json(text, "域名列表"), "域名列表")
    domains = obj.get("data") or []
    if not domains:
        raise ApiError("[passnat] 账号下没有可用域名, 请先在 dashboard.passnat.com 添加")
    best, best_id = "", None
    for d in domains:
        name = d["domain"]
        if full_domain == name or full_domain.endswith("." + name):
            if len(name) > len(best):
                best, best_id = name, d["id"]
    if not best:
        raise ApiError("[passnat] 域名 %s 不在账号域列表(%s)下, 请先添加" % (
            full_domain, ", ".join(d["domain"] for d in domains)))
    log("  passnat 匹配根域名: %s (id=%s)" % (best, best_id))
    return best, best_id


def passnat_add_txt(cfg, domain_id, rec, parent):
    record = rec["record"]
    if parent and record.endswith("." + parent):
        record = record[: -(len(parent) + 1)]
    log("  填写验证记录: %s.%s TXT %s" % (record, parent, rec["value"]))
    payload = {"type": "TXT", "record": record, "value": rec["value"], "domain": domain_id}
    status, text = http(PASSNAT_API + "/user/domain/verify",
                        method="POST", data=payload, extra_headers=passnat_headers(cfg))
    obj = check_code(parse_json(text, "添加验证记录"), "添加验证记录")
    log("  验证记录添加成功 (5分钟有效, 请尽快完成验证)")


# ---------------------------------------------------------------------------
# Step 6: 触发验证 + 轮询 + 下载证书
# ---------------------------------------------------------------------------
def freessl_verify(cfg, order_id):
    """触发验证检查. 返回 'passed'/'failed'/'pending'"""
    status, text = http(FREESSL_BASE + "/api/order/authz/%s?productid=%s" % (order_id, cfg["productid"]),
                        cookies=cfg["freessl_cookie"])
    obj = parse_json(text, "验证检查")
    code = obj.get("code")
    if code == 0 or code == 1235:   # 已通过 / 已通过等待签发
        return "passed"
    if code == 1019 or code == 1800:
        http(FREESSL_BASE + "/api/order/manual/%s" % order_id, cookies=cfg["freessl_cookie"])
        return "pending" if code == 1800 else "failed"


def freessl_wait_issued(cfg, order_id, timeout=600):
    url = FREESSL_BASE + "/api/orders/detail/" + str(order_id)
    deadline = time.time() + timeout
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        status, text = http(url, cookies=cfg["freessl_cookie"])
        obj = parse_json(text, "轮询订单")
        info = (obj.get("msg") or {}).get("info") or {}
        st = info.get("status")
        log("  [%d] 订单状态: %s" % (attempt, st))
        if st == "证书已签发":
            return info
        if st in ("证书申请失败", "校验失败", "验证失败", "订单取消"):
            raise ApiError("[轮询] 订单状态: %s — 详情: %s" % (st, text[:300]))
        time.sleep(10)
    raise ApiError("[轮询] %ss 内未签发, 请到 freessl.cn/orderlist?orderid=%s 查看" % (timeout, order_id))


def freessl_download_cert(cfg, order_id, out_dir):
    log("==> 下载证书")
    status, text = http(FREESSL_BASE + "/api/order/cert/%s?productid=%s" % (order_id, cfg["productid"]),
                        cookies=cfg["freessl_cookie"])
    obj = check_code(parse_json(text, "下载证书"), "下载证书")
    msg = obj.get("msg") or {}
    cert, cacert, key = msg.get("cert"), msg.get("cacert"), msg.get("key")
    if not cert:
        raise ApiError("[下载证书] 响应缺少证书: %s" % text[:400])
    with open(os.path.join(out_dir, "domain.crt"), "w") as f:
        f.write(cert.strip() + "\n")
    log("  domain.crt 已保存")
    if cacert:
        with open(os.path.join(out_dir, "cacert.pem"), "w") as f:
            f.write(cacert.strip() + "\n")
        log("  cacert.pem 已保存")
    if key:
        with open(os.path.join(out_dir, "domain.key"), "w") as f:
            f.write(key.strip() + "\n")
        log("  domain.key 已保存 (服务端返回, 与本地生成一致)")
    if cacert:
        with open(os.path.join(out_dir, "fullchain.pem"), "w") as f:
            f.write(cert.strip() + "\n" + cacert.strip() + "\n")
        log("  fullchain.pem 已保存 (证书+证书链)");


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def cert_days_left(out_dir):
    """读取已有 fullchain.pem 的到期天数; 无证书返回 None, 解析失败返回 0"""
    path = os.path.join(out_dir, "fullchain.pem")
    if not os.path.exists(path):
        return None
    try:
        res = subprocess.run(["openssl", "x509", "-enddate", "-noout", "-in", path],
                             capture_output=True, text=True, timeout=30)
        m = re.search(r"notAfter=(\w+)\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\d{4})", res.stdout)
        if not m:
            return 0
        exp = datetime.strptime("%s %s %s %s" % (m.group(1), m.group(2), m.group(3), m.group(4)),
                                "%b %d %H:%M:%S %Y")
        return (exp - datetime.now(timezone.utc).replace(tzinfo=None)).days
    except Exception:
        pass
    # openssl 不可用时的回退: 根据 info.json 的签发时间估算 (productid 有效期90天)
    try:
        info = json.load(open(os.path.join(out_dir, "info.json"), encoding="utf-8"))
        issued = datetime.fromisoformat(info["issued_at"])
        return 90 - (datetime.now(timezone.utc).replace(tzinfo=None) - issued).days - 2
    except Exception:
        return 0


def check_credentials(cfg):
    """检查 freessl / passnat 的登录凭证是否有效; 任一失效返回 False"""
    log("==> [0] 检查登录凭证")
    ok = True
    try:
        status, text = http(FREESSL_BASE + "/api/profile", cookies=cfg["freessl_cookie"])
        obj = parse_json(text, "freessl凭证")
        if obj.get("code") == 0 and (obj.get("msg") or {}).get("email"):
            log("  freessl.cn  登录有效 (%s)" % obj["msg"]["email"])
        else:
            log("  freessl.cn  登录失效: %s" % text[:200])
            ok = False
    except Exception as e:
        log("  freessl.cn  检查失败: %s" % e)
        ok = False
    try:
        status, text = http(PASSNAT_API + "/user/domain/list", extra_headers=passnat_headers(cfg))
        obj = parse_json(text, "passnat凭证")
        if obj.get("code") == 10000:
            log("  passnat.com 认证有效%s" % (" (API密钥)" if cfg.get("passnat_token") else ""))
        else:
            log("  passnat.com 登录失效: %s" % text[:200])
            ok = False
    except Exception as e:
        log("  passnat.com 检查失败: %s" % e)
        ok = False
    return ok


def ensure_credentials(cfg, auto_login=True):
    """
    凭证检查; freessl 失效时自动调用 captcha_solver 重新登录并刷新 cookie。
    返回 (ok, cfg): ok=凭证是否全部有效, cfg=刷新后的配置
    """
    if check_credentials(cfg):
        return True, cfg
    if not auto_login:
        return False, cfg
    log("==> freessl 登录凭证失效, 自动调用验证码登录刷新 cookie ...")
    try:
        import captcha_solver
        ok = captcha_solver.solve_login(cfg=cfg)
        if ok:
            cfg = json.load(open(CONFIG_FILE, encoding="utf-8"))
            log("==> 自动登录成功, 重新检查凭证")
            return check_credentials(cfg), cfg
        log("==> 自动登录失败(验证码多次未通过)")
    except Exception as e:
        log("==> 自动登录异常: %s" % e)
    return False, cfg


def process_domain(cfg, domain, renew, days, always):
    """处理单个域名: 到期检查 + 申请/续期. 返回 True=成功/无需处理, False=失败"""
    out_dir = os.path.join(BASE_DIR, "output", domain)

    if renew and not always:
        left = cert_days_left(out_dir)
        if left is None:
            log("%s: 未找到现有证书, 首次申请" % domain)
        elif left > days:
            log("%s: 证书还有 %d 天到期 (>%d), 无需续期" % (domain, left, days))
            return True
        else:
            log("%s: 证书还剩 %d 天到期 (<=%d), 开始续期" % (domain, left, days))

    os.makedirs(out_dir, exist_ok=True)

    csr, key = gen_csr(cfg["csr"], cfg["email"], domain, cfg["keytype"], cfg["keysize"])
    with open(os.path.join(out_dir, "domain.csr"), "w") as f:
        f.write(csr + "\n")
    with open(os.path.join(out_dir, "domain.key"), "w") as f:
        f.write(key + "\n")
    log("  已保存: %s/domain.csr, %s/domain.key" % (out_dir, out_dir))

    order_id = freessl_create_order(cfg, domain)
    freessl_submit_csr(cfg, order_id, domain, csr)
    records = freessl_commit(cfg, order_id)

    parent, parent_id = passnat_find_domain(cfg, domain)
    for rec in records:
        passnat_add_txt(cfg, parent_id, rec, parent)

    state = freessl_verify(cfg, order_id)
    if state == "failed":
        log("  !! DNS验证失败, 检查记录是否已生效后稍后重试 (记录5分钟有效)")
        for _ in range(6):
            time.sleep(10)
            state = freessl_verify(cfg, order_id)
            if state == "passed":
                break

    info = freessl_wait_issued(cfg, order_id)
    freessl_download_cert(cfg, order_id, out_dir)

    with open(os.path.join(out_dir, "info.json"), "w") as f:
        json.dump({"domain": domain, "order_id": order_id, "status": info.get("status"),
                   "issued_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat()},
                  f, ensure_ascii=False, indent=2)
    log("\n完成! order_id=%s, 证书文件位于 %s/\n" % (order_id, out_dir))
    return True


def main():
    ap = argparse.ArgumentParser(description="自动化申请SSL证书 (chinassl->freessl->passnat)")
    ap.add_argument("domain", nargs="*",
                    help="要申请证书的域名(可多个); 不填则使用 config.json 中的 domains 列表")
    ap.add_argument("--config", default=CONFIG_FILE, help="配置文件路径(默认 config.json)")
    ap.add_argument("--renew", action="store_true",
                    help="保留兼容: 默认即先检查再申请, 无需该参数")
    ap.add_argument("--days", type=int, default=30,
                    help="续期提前天数(默认30天)")
    ap.add_argument("--always", action="store_true",
                    help="跳过到期检查, 总是重新申请 (重发证书/调试用)")
    ap.add_argument("--no-autologin", action="store_true",
                    help="凭证失效时不自动调用验证码登录(青龙无浏览器依赖时用)")
    args = ap.parse_args()

    if not os.path.exists(args.config):
        sys.exit("找不到配置文件 %s, 请先填写 cookie/邮箱等" % args.config)
    cfg = json.load(open(args.config, encoding="utf-8"))
    if cfg.get("proxy"):
        set_global_proxy(cfg["proxy"])

    if args.domain:
        domains = [d.strip().lower().rstrip(".") for d in args.domain]
    else:
        domains = [d.strip().lower().rstrip(".") for d in (cfg.get("domains") or []) if d.strip()]
    if not domains:
        sys.exit("未指定域名: 请在命令行传域名, 或在 config.json 的 domains 列表中添加")

    ok_cred, cfg = ensure_credentials(cfg, auto_login=not args.no_autologin)
    if not ok_cred:
        print("错误: 登录凭证已失效且自动登录失败 — 请手动运行 python3 captcha_solver.py 更新 freessl_cookie 后重试",
              file=sys.stderr)
        sys.exit(1)

    log("本次处理 %d 个域名: %s" % (len(domains), ", ".join(domains)))
    ok, fail = 0, 0
    for domain in domains:
        log("========== %s ==========" % domain)
        try:
            if process_domain(cfg, domain, not args.always, args.days, args.always):
                ok += 1
        except ApiError as e:
            fail += 1
            print("  [%s] 错误: %s" % (domain, e), file=sys.stderr)
        except urllib.error.HTTPError as e:
            fail += 1
            print("  [%s] HTTP错误: %s %s — 可能是cookie过期, 请刷新 config.json" % (domain, e.code, e.reason),
                  file=sys.stderr)

    log("\n全部处理完成: 成功 %d, 失败 %d" % (ok, fail))
    sys.exit(0 if fail == 0 else 1)


if __name__ == "__main__":
    main()