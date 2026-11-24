# ProxyGuard 0.4.0

Windows 后台守护程序。监控 `codex.exe` 与 `claude.exe` 的出口国家：当本机公网出口不在允许国家内（通常是 VPN 断开）时，立即为这两个程序写入 Windows 防火墙出站阻断规则，并弹出窗口提示。

## 使用方式（安装即用）

1. 运行 `ProxyGuard_0.4.0_x64-setup.exe`，在 UAC 弹窗中点“是”。这是唯一需要的管理员授权：用于写入防火墙规则，并注册开机自启计划任务（最高权限，运行时不再弹 UAC）。
2. 安装完成后守护进程自动运行，托盘图标常驻。
3. 在面板中选择“允许的出口国家”（默认 US）。
4. 启动一次 Codex 或 Claude，程序路径会被登记，之后即使它们没在运行，阻断规则也会生效。

卸载时安装器会先删除本程序创建的所有防火墙规则，再删除计划任务。

## 行为

- 每 5 秒检测一次本机公网出口 IP（`api.ipify.org`），IP 变化时才查询国家（`ipwho.is`）。
- 国家不在允许范围：立即写入阻断规则，窗口弹出，显示“当前 VPN 已断开”。
- 国家恢复为允许范围：自动删除规则，目标程序恢复联网。
- 连续两次无法检测出口国家：按失败处理，阻断目标程序（防止在无法确认时泄露）。
- 关闭窗口只是隐藏到托盘，守护继续运行。托盘“退出”会停止守护，但已写入的阻断规则保留，直到下次启动重新判定。

## 构建（需要 Windows）

需要 Node.js LTS、Rust（MSVC 工具链）、Microsoft C++ Build Tools、WebView2 Runtime。

```powershell
npm install
npx tauri icon .\app-icon.png   # 首次构建前生成 src-tauri/icons，源码包未包含图标
npm run desktop:build           # 产物位于 src-tauri\target\release\bundle\nsis\
```

## 已知边界（请务必阅读）

- **不是零泄露的内核级开关。** 检测有 5 秒间隔，规则写入需要几百毫秒，期间可能有流量通过。
- **已建立的 TCP 连接不一定被立即切断**，通常在连接重建时生效。
- **按程序路径阻断。** 只能覆盖 `codex.exe` / `claude.exe` 本体。Claude Code 若以 `node.exe` 运行 CLI（npm 安装方式），无法按程序精确阻断，且不会为了它去阻断 node.exe（会误伤其他程序）。Claude 桌面版的子进程若路径不同，也不会被覆盖。
- **检测的是本机系统出口**，不是每个进程的实际出口。若目标程序绕过系统路由（例如自带代理），检测结果不能代表它的真实出口。
- **GeoIP 是数据库归属**，不等同于物理位置。
- **需要管理员权限运行**：如果以普通用户启动，防火墙写入会失败，界面会显示错误，不会误报为已阻断。
- **第三方服务**：公网 IP 与国家查询分别发送到 `api.ipify.org` 和 `ipwho.is`。在受管设备上使用前请确认组织政策。
- 这是一个守护工具，不修改 WDAC、Defender 或任何系统安全策略。

## 与 0.3.0 的区别

0.3.0 是按“代理端点 + 软件组 + 每次 UAC”设计的原型。0.4.0 面向系统级 VPN，去掉了代理配置，只监控 Codex / Claude，改为安装时一次授权、后台常驻、开机自启。
<img width="1803" height="1471" alt="image" src="https://github.com/user-attachments/assets/0e37858d-1d69-4dd6-b1eb-e6093a2bf8a4" />检测中
<img width="1785" height="1475" alt="image" src="https://github.com/user-attachments/assets/f5079db3-a953-4584-9434-a560ad793ae3" />放行
<img width="1828" height="1483" alt="image" src="https://github.com/user-attachments/assets/df563efb-c394-4736-b8c6-131ecfc11f0c" />断开




