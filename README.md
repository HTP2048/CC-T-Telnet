# CC:Tweaked Telnet

用于 CC:Tweaked 的类Telnet服务端/客户端程序
支持智能多设备抢占、密码认证及外部monitor

## ✨ 核心特性

* **端到端加密**：内置 XXTEA (CBC 模式) 加密算法，保障 Rednet 握手过程的安全，防止密码泄露。
* **双模一体**：一个轻量级 Lua 脚本同时囊括服务端与客户端的全部逻辑。
* **实时终端投屏**：服务端自动拦截终端输出，客户端可实时查看远程服务器的 Shell 画面。
* **全事件同步**：支持客户端将全部键盘事件 (`key`, `char`, `paste`等)透传至服务端。
* **高级外设支持**：服务端支持将画面重定向至外接显示器 (`monitor`)。
* **连接控制**：支持抢占模式与独占模式 (`exclusive`) 管理多客户端冲突，内置超时掉线检测。

---

## 📦 安装与准备

1. 确保你的 CC:T 版本匹配可用版本列表中的版本
2. 确保你的 ComputerCraft 电脑已装备 **无线调制解调器 (Wireless Modem)** 或 **末影调制解调器 (Ender Modem)**。
3. 在电脑中运行以下命令下载本程序（需要服务器开启 HTTP API）：

```CraftOS
wget https://raw.githubusercontent.com/HTP2048/CC-T-Telnet/refs/heads/main/telnet.lua telnet.lua

```

---

## 🚀 使用指南

程序的命令行参数经过结构化设计，支持长短参数混合使用。

### 启动服务端 (Server Mode)

在目标电脑上启动 Telnet 服务，指定通信协议与密码进行挂载监听。

**基础启动：**

```bash
telnet server -p my_protocol -pw my_secure_password

```

**连接显示器并开启独占模式：**
*(独占模式下，如果已有客户端连接，在已连接客户端仍有响应的前提下新的连接请求将被拒绝)*

```bash
telnet server -p my_protocol -pw my_secure_password -m -e

```

### 启动客户端 (Client Mode)

在你的本地电脑上启动客户端，输入相同的协议与密码，并指定服务端的 Computer ID。

**连接至 ID 为 12 的服务器：**

```bash
telnet client 12 -p my_protocol -pw my_secure_password

```

---

## ⚙️ 命令行参数说明

| 参数名 / 位置 | 简写 / 别名 | 类型 | 描述 | 默认值 |
| --- | --- | --- | --- | --- |
| `mode` (位置 1) | 无 | String | **[必填]** 运行模式：`server` 或 `client` | 无 |
| `host` (位置 2) | `-h`, `--server`, `--id` | Number | **[客户端必填]** 远程服务器的 Computer ID | 无 |
| `--protocol` | `-p`, `--proto` | String | **[必填]** Rednet 通信协议名称 | 无 |
| `--password` | `-pw`, `--pwd` | String | 连接密码 | `""` (空) |
| `--monitor` | `-m`, `--display` | Bool | 服务端是否启用外接显示器 | `false` |
| `--exclusive` | `-e`, `--excl`, `--exc` | Bool | 服务端是否开启独占模式 (关闭则新连接直接踢掉老连接) | `false` |

---

## 📄 一些其他的细节

* 客户端的terminate会被透传至服务端，所以你在客户端执行停止其实是停止了服务端，如果想单独停止客户端，请直接点击关机按钮。
* 代码中的注释请全部阅读一遍，会有些可以配置的地方

Copyright (c) 2026 HTP2048
