# autossl — SSL 证书全自动申请/续期系统

基于 3 个站点自动完成证书申请：**csr.chinassl.net 生成 CSR → freessl.cn 申请证书 → dashboard.passnat.com 填写 DNS 验证记录**，支持多域名管理与到期自动续期。

## 项目结构

```
autossl/
├── autossl.py            # 主脚本: CSR生成→申请→验证→下载 (自动续期入口)
├── captcha_solver.py     # 登录辅助: 腾讯验证码 Gemini 识别 + 有头浏览器自动点击
├── captcha_tool.py       # 旧版人工协作工具(已废弃, 保留参考)
├── probe_login.py        # 验证码探针(调试用, 可删除)
├── config.json           # 配置文件(账号/域名/cookie/Gemini keys)
├── captcha/              # 验证码截图与识图产物
├── output/<域名>/        # 证书输出目录
│   ├── domain.csr        # 证书签名请求
│   ├── domain.key        # 私钥
│   ├── domain.crt        # 证书(leaf)
│   ├── cacert.pem        # 中间证书链
│   ├── fullchain.pem     # 完整证书链 (= domain.crt + cacert.pem, 部署用)
│   └── info.json         # 订单信息/签发时间
├── freessl.cn/           # 网站存档(研究资料)
├── dashboard.passnat.com/# 网站存档(研究资料)
├── csr.chinassl.net/     # 网站存档(研究资料)
├── freessl_Proofs.md / passnetapi_Proofs.md  # 抓包凭证存档
└── docs/API.md           # 逆向出的完整 API 文档
```

## 环境与运行(虚拟环境)

本项目依赖已隔离在项目内 `.venv/`(含浏览器, 约600MB)。**删除 `.venv` 即完全清除, 不污染系统**。

```bash
# 首次搭建(已完成, 重装时执行):
python3 -m venv .venv
.venv/bin/pip install playwright pillow
PLAYWRIGHT_BROWSERS_PATH=$PWD/.venv/ms-playwright .venv/bin/playwright install chromium

# 日常运行(注意用 .venv 里的 python):
.venv/bin/python3 autossl.py [域名|--renew|--always|--days N]
.venv/bin/python3 captcha_solver.py
```

> 脚本会自动检测 `.venv/ms-playwright` 并设置浏览器路径, 无需手动带环境变量。

### 1. 配置文件 `config.json`

```jsonc
{
  "email": "freessl账号邮箱",
  "freessl_password": "账号密码(仅captcha_solver用)",
  "gemini_api_keys": ["key1", "key2", "..."],   // 多key自动轮询
  "gemini_model": "gemini-3.5-flash",
  "gemini_proxy": "http://Clash:pfabkvBh@192.168.31.99:7890", // 可选, 脚本已默认集成
  "productid": "trustasiafree01",                // 免费90天单域名
  "authmethod": "dns",
  "keytype": "rsa",
  "keysize": "2048",
  "domains": ["huhan3nd.odn.cc"],                // 要管理的域名列表
  "csr": { "company": "...", "department": "...", "city": "...",
           "province": "...", "country": "CN" },
  "freessl_cookie": "...",                       // freessl.cn 会话cookie
  "passnat_token": "sk_xxx"                      // passnat API密钥(推荐, 永不过期)
  // "passnat_cookie": "..."                     // 或退回cookie方式(会过期)
}
```

> 域名必须是 dashboard.passnat.com 账号下已添加(ICP备案)的域名。

### 2. 申请/续期 `python3 autossl.py`

默认**智能模式**: 先检查已有证书, 到期 <=30 天或无证书才申请; 有效则跳过。

```
python3 autossl.py              # 处理 config.json 里所有域名(推荐, 青龙直接跑这个)
python3 autossl.py abc.com      # 只处理指定域名
python3 autossl.py --always     # 跳过检查, 强制重新申请
python3 autossl.py --days 60    # 调整续期提前天数(默认30)
```

每轮先验证 freessl/passnat 的 cookie 是否有效(失效立即报错退出, exit 1)。
证书文件统一输出到 `output/<域名>/`, 服务器部署路径不变, 续期后无需改配置。

### 3. 登录刷新 cookie `python3 captcha_solver.py`

当 freessl 的 SESSION_ID 过期时, 用浏览器+Gemini 自动完成腾讯验证码并登录:

- 有头浏览器自动填账号密码 → 触发验证码
- 抓取指令条(170x50)与挑战图(672x480), Gemini 识别目标序列+标记坐标
- 自动依次点击 → 确定 → 新 SESSION_ID 写回 config.json
- 每轮 60 秒时间箱, 超时重新第一步, 最多 3 轮; Gemini 多 key 轮询
- 需要桌面环境(弹浏览器), 适合本机手动跑; 验证码 3 次失败时人工浏览器登录
- 时效注意: 谷歌免费 key 每天约 20 次请求, 用多 key 轮换

## 自动登录联动

`autossl.py` 每次运行先检查凭证；**freessl 登录失效时自动调用 `captcha_solver.py` 重新登录并刷新 cookie**（实测链路：凭证失效→自动弹浏览器→Gemini识别验证码→点击→新SESSION_ID写回→继续续期流程）。

- `--no-autologin`：禁用自动登录（凭证失效直接报错退出）
- 青龙/无显示器环境自动走 headless 模式（`DISPLAY` 不存在时）
- 单独运行登录：`.venv/bin/python3 captcha_solver.py [--headless] [--rounds N]`

## 青龙面板部署

```
1. 上传 autossl.py + captcha_solver.py + config.json + .venv/ 到 /ql/scripts/
   (或青龙里: pip install playwright pillow && playwright install chromium)
2. 新建定时任务: 命令填原始命令 (不要用 task 前缀会吞参数):
     python3 autossl.py     ← 凭证失效会自动尝试验证码登录(headless)
   定时规则建议: 30 4 1,16 * *    (每月1/16号, 90天证书留足余量)
3. 通知设置开启失败推送; 若自动登录连续失败会 exit 1 推送提醒
```

> 注意: 青龙容器是数据中心IP, 腾讯验证码难度可能更高, 自动登录失败时需在有桌面的机器
> 上手动跑 `python3 captcha_solver.py` 一次, 或人工浏览器登录更新 freessl_cookie。

## 已知坑 (全部实测踩过)

| 坑 | 说明 |
|---|---|
| 表单编码 | freessl keymanager API 必须 `application/x-www-form-urlencoded`, JSON 会报 `1002 邮箱格式不正确` |
| CSR 字段名 | `/api/keymanager/order/csr/submit` 的字段是 **`csr`** 不是 `csrpem` |
| commit 字段 | `/api/keymanager/order/commit` 用 `order_id=xxx` 表单字段, 响应里有 DNS 验证记录 `auth_info` |
| 验证记录时效 | passnat 临时 TXT 记录只活 **5 分钟**, 填完要立即触发验证 |
| 证书下载 | `GET /api/order/cert/<id>?productid=` 返回 `{cert, cacert, key}`, 直接合并 fullchain |
| 登录验证码 | 强制腾讯"依次点击"验证码(无感/滑块不会放行), `ticket` 只能浏览器环境获取, 纯 API 不可能绕过 |
| 模拟点击风控 | 不要额外点挑战图中心(探测点击会被记录为一次点击导致序列错乱); 不要 page.screenshot(会闪); 红点标注必须挂 document.body(tcaptcha 容器带 transform 会偏移 fixed 定位) |
| Gemini 图题 | 新版"AI生成背景"验证码含图标目标(如柱状图/猫), flash-lite 识别不了, 用 3.5-flash; 分步识别(先指令条后标记)命中率更高 |

更完整接口文档见 [docs/API.md](docs/API.md)。