# 42IPwin - Windows 多IP SOCKS5 代理管理面板

一台 Windows 主机接 3 条公网网线，每条线跑独立 SOCKS5 实例 + 一个 Web 管理后台，可创建/删除/启停代理用户。

## 功能

- **多线路支持**：每条公网网线绑定一个 SOCKS5 端口
- **Web 管理后台**：
  - 仪表盘（流量趋势、线路状态、实时日志）
  - 线路/IP 管理（新建/编辑/删除/启停/出口测试）
  - 代理用户管理（新建/改密/启停/到期/流量/复制连接信息）
  - 3proxy 服务控制（启动/停止/重载）
  - 修改后台密码
- **流量统计**：每用户按小时聚合，3proxy counter 驱动
- **自动重载**：后台任意变动自动重写 `3proxy.cfg` 并热重载 3proxy

## 系统架构

```
网线1 (公网IP-A) ──┐
网线2 (公网IP-B) ──┼──► 3proxy.exe (3个SOCKS5实例)  ──► 公网用户
网线3 (公网IP-C) ──┘             ▲
                                │ 自动生成 cfg
                                │
                ┌───────────────┴───────────────┐
                │   Web 管理后台 (Flask)         │
                │   http://127.0.0.1:8080       │
                │   - 线路/IP 管理               │
                │   - 代理用户管理               │
                │   - 流量/连接监控              │
                │   SQLite 存储                 │
                └───────────────────────────────┘
```

## 目录结构

```
d:\42IPwin\
├── 3proxy\
│   ├── 3proxy.exe           # 主程序（install.bat 自动下载）
│   ├── 3proxy.cfg           # 配置文件（后台自动生成）
│   ├── 3proxy.pid           # PID 文件
│   └── logs\
├── panel\
│   ├── app.py               # Flask 入口
│   ├── config.py            # 全局配置
│   ├── models.py            # 数据库模型
│   ├── requirements.txt
│   ├── routes\              # API 路由
│   ├── services\            # 业务逻辑（cfg 生成、3proxy 管理、流量采集）
│   ├── templates\           # 前端页面
│   └── static\              # CSS/JS
├── data\
│   ├── panel.db             # SQLite
│   └── counters\            # 3proxy 流量计数
├── install.bat              # 一键安装
├── start.bat                # 一键启动
└── stop.bat                 # 一键停止
```

## 部署步骤

### 1. 准备
- Windows 10/11 或 Windows Server 2016+
- Python 3.8+ （[下载](https://www.python.org/downloads/)，安装时勾选 "Add to PATH"）
- 3 条网线已接入，网卡分别有公网 IP

### 2. 安装
右键 `install.bat` → **以管理员身份运行**

脚本会：
1. 创建目录结构
2. 下载 3proxy
3. 安装 Python 依赖
4. 初始化数据库
5. 配置 Windows 防火墙（放行 10801-10803 + 8080）

### 3. 启动
双击 `start.bat`，会同时启动管理后台和 3proxy。

### 4. 访问后台
浏览器打开 `http://127.0.0.1:8080`

默认账号：`admin` / `admin123`（**登录后立即修改！**）

### 5. 添加线路
进入"线路管理" → "新建线路"，填写：
- 线路名（如"网线1-电信"）
- 公网IP（如 `203.0.113.1`）
- SOCKS5 端口（默认 10801/10802/10803）

### 6. 添加代理用户
进入"代理用户" → "新建用户"，填写：
- 用户名、密码
- 绑定到哪条线路
- 可选：到期时间、备注

完成后把连接信息发给用户：
```
socks5://203.0.113.1:10801
用户: user001
密码: ********
```

## 外部使用

任何支持 SOCKS5 的工具都可以：
- **浏览器**：SwitchyOmega 之类插件
- **命令行**：`curl --socks5 203.0.113.1:10801 -U user001:password https://example.com`
- **代码**：`requests` 的 `proxies={'https': 'socks5://user001:password@203.0.113.1:10801'}`
- **Proxifier / SocksCap**：全局代理

## 常见问题

**Q: 外部连接提示 "Connection refused"？**
A: 检查 Windows 防火墙是否放行了对应端口（install.bat 会自动配置）；检查 3proxy 是否启动；检查 IP 是否正确绑定到对应网卡。

**Q: 后台修改了线路/用户，但客户端没生效？**
A: 后台会自动重载 3proxy，请等待 2-3 秒再试。

**Q: 想限制某个用户流量？**
A: 3proxy 配置支持 `users user:CL:pass:bandwidth:conns`，可在 `cfg_generator.py` 中扩展。当前版本通过 `bytes_in/out` 字段记录实际使用量，可手动监控或自行加上限逻辑。

**Q: 流量统计准确吗？**
A: 基于 3proxy `counter` 指令，按 3proxy 的 8 小时清零机制会有一定偏差，但整体趋势准确。生产环境建议配合外部计费系统。

**Q: 如何备份？**
A: 只需备份 `data\panel.db`（含所有线路/用户/流量历史）。

## 安全建议

1. **改默认密码**：登录后立即改 admin 密码
2. **限制后台访问**：通过 Windows 防火墙限制 8080 端口只允许本机/内网访问
3. **强代理密码**：用户密码至少 8 位以上字母数字混合
4. **定期审计**：查看实时日志，排查异常 IP
5. **关闭不用的线路**：在"线路管理"中停用，避免空暴露

## 目录性能参考

- 3proxy 本身极轻（< 5MB 内存/实例）
- Flask 后台约 30-50MB
- SQLite 单库支持 10 万级用户无压力

## License

仅供合法用途使用。
