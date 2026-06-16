# 42IPwin PVE 一键部署

目标机器必须是 Proxmox VE 8.x 宿主机，并且能执行：

```bash
qm list
pveversion
```

## 上传项目后执行

把整个 `42IPwin` 项目上传到 PVE 宿主机，例如 `/root/42IPwin`，然后执行：

```bash
cd /root/42IPwin
bash install_pve.sh
```

安装完成后访问：

```text
http://PVE服务器IP:8080
```

## 使用 Git 仓库一键安装

如果项目已经放到 Git 仓库，可以在 PVE 宿主机执行：

```bash
curl -fsSL https://你的域名/install_pve.sh -o install_pve.sh
GIT_REPO=https://你的git仓库地址 bash install_pve.sh
```

## 服务命令

```bash
systemctl status 42ipwin --no-pager
systemctl restart 42ipwin
journalctl -u 42ipwin -f
```

## 注意

- 不要在普通 Ubuntu/Debian 虚拟机里执行，PVE 模块需要 `qm` 命令。
- 面板服务默认安装到 `/opt/42IPwin`。
- 面板默认端口是 `8080`。
