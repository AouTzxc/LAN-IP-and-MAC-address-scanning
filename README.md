# 局域网 IP/MAC 扫描器

这是一个使用 Python + PyQt5 编写的 Windows 桌面程序，用于扫描当前局域网内设备的 IP 地址和 MAC 地址，并记录发现时间。扫描结果可以导出为 TXT 文件。

## 安装依赖

```powershell
pip install -r requirements.txt
```

## 运行

```powershell
python main.py
```

也可以双击 `run.bat` 启动。

## 使用说明

1. 启动程序后，在顶部选择要扫描的本机网段。
2. 点击“开始扫描”。
3. 扫描完成后，表格会显示 IP 地址、MAC 地址、发现时间和网卡名称。
4. 点击“导出 TXT”保存当前结果。

## 注意事项

- 本工具主要扫描同一二层局域网内的设备。跨路由器、跨 VLAN 或被防火墙隔离的设备可能无法显示 MAC 地址。
- 某些设备如果禁止响应 ICMP，仍可能通过 ARP 表被发现；但如果系统没有获取到 ARP 记录，就无法显示其 MAC。
- 在 Windows 上，程序会优先使用 `Get-NetIPAddress` 和 `Get-NetNeighbor` 获取网络与邻居信息，兼容性不足时会回退到 `ipconfig`/`arp -a`。
