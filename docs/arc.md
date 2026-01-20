# Webtop 用户中心架构（内置 Traefik 入口）

## 总体思路
- 目标：只做 Webtop 的统一用户中心和入口控制，不泛化成其他系统；支持管理局域网内的多台 Webtop（容器或裸机），未登录用户无法直连。
- 形态：单个 Go 用户中心（门户+后台+鉴权）+ 内置 Traefik 网关（同一 docker-compose 跑），所有请求先到 Traefik，再通过 ForwardAuth 鉴权后转发到 Webtop。
- 暴露端口：对外只暴露 Traefik 的 80/443；Webtop 实例（本机或局域网其他机器）仅在内网可达，不映射公网。

## 模块划分
- Portal：登录后显示可访问的 Webtop 列表，点击进入。
- Admin：用户、角色、Webtop 目标（名称/URL/启用）维护；角色与 Webtop 关联；审计变更。
- Auth：本地用户名密码（bcrypt）+ 可选 TOTP；登录限速；失败 3 次锁 5 分钟，后续阶梯/指数延长，最长锁定 1 年；会话 Cookie 签名（HttpOnly、Secure）。
- Traefik 网关：所有入口路由到各 Webtop，使用 ForwardAuth 调 Go 的 `/auth/check` 做登录态校验；透传 WebSocket（适配 noVNC）；支持将路由指向局域网其他机器的 Webtop 地址。
- Store：SQLite 持久化（用户、角色、Webtop 配置、会话、锁定记录）；Webtop 目标可填写内网 URL。

## 数据模型（SQLite 草稿）
- users(id, username unique, password_hash, totp_secret?, created_at, disabled, locked_until)
- roles(id, name)
- user_roles(user_id, role_id)
- webtops(id, name, target_url, enabled)
- role_webtops(role_id, webtop_id)
- sessions(id, user_id, expires_at)
- login_attempts(id, user_id, attempted_at, success)

## 关键流程
- 登录：用户名密码（可选 TOTP）校验 -> 签发会话 Cookie；失败计数触发锁定（3 次锁 5 分钟，重复递增，最长 1 年）。
- 访问：浏览器请求 `/webtop/{id}`（或统一前缀）；Traefik 路由命中后先发子请求到 `/auth/check`，返回 2xx 表示已登录；通过后 Traefik 反代到对应 Webtop 容器或局域网实例。若 Webtop 需要根路径访问，配合 StripPrefix 中间件去掉 `/webtop/{id}` 前缀，或改用基于域名的路由避免路径改写。
- WebSocket/noVNC：Traefik 保持 `Upgrade/Connection` 头，ForwardAuth 对握手请求同样生效；未登录握手被拒绝。

## HTTP 接口概览
- Portal：`POST /login`、`POST /logout`、`GET /portal`（Webtop 列表）。
- Auth：`GET /auth/check`（Traefik ForwardAuth 使用，返回 2xx/403）。
- Admin：`GET/POST /admin/users`、`/admin/roles`、`/admin/webtops`、`/admin/role-webtops`；可加 `/admin/audit`。
- （无 CAS：本方案专注 Webtop 用户中心，不提供 CAS 端点）。

## 安全与运维
- 仅 Traefik 对外，Webtop 内网访问；强制 HTTPS；Cookie `Secure`、`HttpOnly`、`SameSite=Lax`；密钥可轮换。
- 登录限速与锁定策略落库，后台可解锁；审计关键操作；结构化日志。

## 部署要点
- 典型 compose：`traefik`（entrypoints web/websecure + ForwardAuth）+ `user-center`（Go 应用）+ 若干本机 Webtop 容器。
- 跨机器 Webtop：只需保证 Traefik 能访问这些内网 Webtop 地址（如 `http://192.168.x.x:3000`），在后台将 URL 配置为该内网地址；Traefik 路由服务指向该 URL，仍套用 ForwardAuth。
- 网络：`webtop` 容器仅加入内部网络；`traefik` 同时加入内部和外部（暴露 80/443）；对外不暴露 Webtop 端口。
- Traefik 路由示意：
  - `PathPrefix("/webtop/1")` -> service webtop1，middlewares `[auth]`。
  - 若使用路径前缀，添加 StripPrefix 以便 Webtop 静态资源/WS 请求按根路径工作；或改用不同子域名路由。
  - `auth` 中间件：forwardAuth.address = `http://user-center:8080/auth/check`，信任前向头。
- Portal 可提供静态入口页，链接指向 `/webtop/{id}` 前缀。
