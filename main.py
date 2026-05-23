import ipaddress
import ctypes
import json
import os
import re
import socket
import subprocess
import sys
import unicodedata
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime

from PyQt5.QtCore import QThread, Qt, pyqtSignal
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import (
    QApplication,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QComboBox,
    QCheckBox,
    QProgressBar,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)


def resource_path(relative_path):
    base_path = getattr(sys, "_MEIPASS", os.path.abspath("."))
    return os.path.join(base_path, relative_path)


@dataclass(frozen=True)
class NetworkInfo:
    address: str
    prefix_length: int
    interface_alias: str
    local_mac: str = ""
    interface_description: str = ""

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(f"{self.address}/{self.prefix_length}", strict=False)

    def label(self) -> str:
        adapter_name = self.interface_description or self.interface_alias
        return f"{self.network}  |  {adapter_name}  |  本机 {self.address}"


@dataclass
class DeviceRecord:
    device_name: str
    ip: str
    mac: str
    found_at: str
    interface_alias: str = ""


def hidden_subprocess_kwargs():
    kwargs = {}
    if sys.platform.startswith("win"):
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        kwargs["startupinfo"] = startupinfo
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return kwargs


def run_command(command, timeout=20):
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        encoding="utf-8",
        errors="ignore",
        **hidden_subprocess_kwargs(),
    )
    return completed.stdout.strip()


def powershell_json(script, timeout=20):
    utf8_script = (
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
        "$OutputEncoding = [System.Text.Encoding]::UTF8; "
        f"{script}"
    )
    output = run_command(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            utf8_script,
        ],
        timeout=timeout,
    )
    if not output:
        return []
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        return [data]
    return data if isinstance(data, list) else []


def get_networks_from_powershell():
    script = (
        "Get-NetIPAddress -AddressFamily IPv4 | "
        "Where-Object { $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1' "
        "-and $_.PrefixLength -gt 0 -and $_.PrefixLength -le 32 } | "
        "ForEach-Object { "
        "$adapter = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue; "
        "[PSCustomObject]@{ IPAddress=$_.IPAddress; PrefixLength=$_.PrefixLength; "
        "InterfaceAlias=$_.InterfaceAlias; MacAddress=$adapter.MacAddress; "
        "InterfaceDescription=$adapter.InterfaceDescription } "
        "} | ConvertTo-Json"
    )
    networks = []
    for item in powershell_json(script):
        address = str(item.get("IPAddress", "")).strip()
        prefix = item.get("PrefixLength")
        alias = str(item.get("InterfaceAlias", "")).strip()
        mac = normalize_mac(item.get("MacAddress", ""))
        description = str(item.get("InterfaceDescription", "")).strip()
        try:
            ipaddress.ip_address(address)
            prefix_length = int(prefix)
            networks.append(NetworkInfo(address, prefix_length, alias or "未知网卡", mac, description))
        except (TypeError, ValueError):
            continue
    return dedupe_networks(networks)


def get_networks_from_socket():
    networks = []
    host_name = socket.gethostname()
    try:
        addresses = socket.gethostbyname_ex(host_name)[2]
    except socket.gaierror:
        addresses = []

    for address in addresses:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_link_local:
            continue
        networks.append(NetworkInfo(str(ip), 24, "自动检测网卡", "", "自动检测网卡"))
    return dedupe_networks(networks)


def dedupe_networks(networks):
    seen = set()
    result = []
    for network_info in networks:
        try:
            key = (
                str(network_info.network),
                network_info.address,
                network_info.interface_alias,
                network_info.local_mac,
                network_info.interface_description,
            )
        except ValueError:
            continue
        if key in seen:
            continue
        seen.add(key)
        result.append(network_info)
    return result


def load_networks():
    networks = get_networks_from_powershell()
    if networks:
        return networks
    return get_networks_from_socket()


def ping_ip(ip, timeout_ms):
    if sys.platform.startswith("win"):
        command = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        timeout_seconds = max(1, int(timeout_ms / 1000))
        command = ["ping", "-c", "1", "-W", str(timeout_seconds), ip]
    try:
        subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=max(2, timeout_ms / 1000 + 1),
            **hidden_subprocess_kwargs(),
        )
    except (subprocess.SubprocessError, OSError):
        pass


def send_arp(ip):
    if not sys.platform.startswith("win"):
        return ""
    try:
        destination_ip = ctypes.windll.ws2_32.inet_addr(ip.encode("ascii"))
        if destination_ip == 0xFFFFFFFF:
            return ""
        mac_buffer = (ctypes.c_ubyte * 6)()
        mac_length = ctypes.c_ulong(6)
        result = ctypes.windll.iphlpapi.SendARP(
            ctypes.c_ulong(destination_ip),
            ctypes.c_ulong(0),
            ctypes.byref(mac_buffer),
            ctypes.byref(mac_length),
        )
    except (AttributeError, OSError, ValueError):
        return ""
    if result != 0 or mac_length.value != 6:
        return ""
    return ":".join(f"{byte:02X}" for byte in mac_buffer)


def scan_ip_for_mac(ip, timeout_ms):
    mac = send_arp(ip)
    if mac:
        return mac
    ping_ip(ip, min(timeout_ms, 300))
    return send_arp(ip)


def resolve_dns_name(ip):
    try:
        name = socket.gethostbyaddr(ip)[0].strip()
    except (socket.herror, socket.gaierror, OSError):
        return ""
    return name


def resolve_netbios_name(ip):
    if not sys.platform.startswith("win"):
        return ""
    try:
        output = run_command(["nbtstat", "-A", ip], timeout=3)
    except (subprocess.SubprocessError, OSError):
        return ""

    for line in output.splitlines():
        match = re.match(r"\s*([^\s<>]{1,15})\s+<00>\s+UNIQUE", line, re.IGNORECASE)
        if match:
            name = match.group(1).strip()
            if name and name != "__MSBROWSE__":
                return name
    return ""


def resolve_device_name(ip, fallback="未知设备"):
    name = resolve_dns_name(ip) or resolve_netbios_name(ip)
    return name or fallback


def normalize_mac(mac):
    mac = str(mac or "").strip().replace("-", ":").upper()
    if re.fullmatch(r"([0-9A-F]{2}:){5}[0-9A-F]{2}", mac):
        return mac
    return ""


def get_neighbors_from_powershell():
    script = (
        "$adapters = Get-NetAdapter | Select-Object ifIndex,InterfaceDescription,InterfaceAlias; "
        "Get-NetNeighbor -AddressFamily IPv4 | "
        "Where-Object { $_.LinkLayerAddress -and $_.LinkLayerAddress -ne '00-00-00-00-00-00' } | "
        "ForEach-Object { "
        "$neighbor = $_; "
        "$adapter = $adapters | Where-Object { $_.ifIndex -eq $neighbor.ifIndex } | Select-Object -First 1; "
        "[PSCustomObject]@{ IPAddress=$neighbor.IPAddress; LinkLayerAddress=$neighbor.LinkLayerAddress; "
        "State=$neighbor.State; InterfaceAlias=$neighbor.InterfaceAlias; "
        "InterfaceDescription=$adapter.InterfaceDescription } "
        "} | ConvertTo-Json"
    )
    neighbors = {}
    for item in powershell_json(script):
        ip = str(item.get("IPAddress", "")).strip()
        mac = normalize_mac(item.get("LinkLayerAddress", ""))
        alias = str(item.get("InterfaceAlias", "")).strip()
        description = str(item.get("InterfaceDescription", "")).strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        if mac:
            neighbors[ip] = (mac, description or alias)
    return neighbors


def get_neighbors_from_arp():
    neighbors = {}
    try:
        output = run_command(["arp", "-a"], timeout=10)
    except (subprocess.SubprocessError, OSError):
        return neighbors

    for line in output.splitlines():
        match = re.search(
            r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+"
            r"(?P<mac>(?:[0-9a-fA-F]{2}[-:]){5}[0-9a-fA-F]{2})",
            line,
        )
        if not match:
            continue
        ip = match.group("ip")
        mac = normalize_mac(match.group("mac"))
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        if mac:
            neighbors[ip] = (mac, "")
    return neighbors


def load_neighbors():
    neighbors = get_neighbors_from_arp()
    if neighbors:
        return neighbors
    return get_neighbors_from_powershell()


def text_display_width(value):
    width = 0
    for char in str(value):
        width += 2 if unicodedata.east_asian_width(char) in ("F", "W") else 1
    return width


def pad_display(value, width):
    text = str(value)
    padding = max(0, width - text_display_width(text))
    return text + (" " * padding)


def build_aligned_txt(records):
    rows = [
        ("设备名称", "IP 地址", "MAC 地址", "发现时间", "网卡"),
    ]
    rows.extend(
        (record.device_name, record.ip, record.mac, record.found_at, record.interface_alias)
        for record in sorted(records, key=lambda item: ipaddress.ip_address(item.ip))
    )

    column_widths = []
    for column in range(5):
        max_width = max(text_display_width(row[column]) for row in rows)
        column_widths.append(max_width + 4)

    lines = []
    for row in rows:
        lines.append(
            "".join(pad_display(value, column_widths[index]) for index, value in enumerate(row)).rstrip()
        )
    return lines


class ScanWorker(QThread):
    progress_changed = pyqtSignal(int, int)
    status_changed = pyqtSignal(str)
    device_found = pyqtSignal(object)
    finished_scan = pyqtSignal(int)

    def __init__(self, network_info, timeout_ms, resolve_names=False, max_workers=128):
        super().__init__()
        self.network_info = network_info
        self.timeout_ms = timeout_ms
        self.resolve_names = resolve_names
        self.max_workers = max_workers
        self._stop_requested = False
        self._known_ips = set()

    def request_stop(self):
        self._stop_requested = True

    def run(self):
        network = self.network_info.network
        hosts = [str(ip) for ip in network.hosts()]
        total = len(hosts)
        if total == 0:
            self.finished_scan.emit(0)
            return

        self.status_changed.emit(f"正在快速扫描 {network}，共 {total} 个地址")
        self.emit_local_machine()
        completed = 0
        workers = max(1, min(self.max_workers, total))

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(scan_ip_for_mac, ip, self.timeout_ms): ip for ip in hosts}
            for future in as_completed(futures):
                if self._stop_requested:
                    for pending_future in futures:
                        pending_future.cancel()
                    break
                completed += 1
                self.progress_changed.emit(completed, total)
                ip = futures[future]
                try:
                    mac = future.result()
                except Exception:
                    mac = ""
                if mac:
                    self.emit_device(ip, mac)

        self.status_changed.emit("正在读取 ARP/邻居表")
        self.emit_current_neighbors(network)
        self.finished_scan.emit(len(self._known_ips))

    def emit_local_machine(self):
        if not self.network_info.local_mac:
            return
        found_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._known_ips.add(self.network_info.address)
        self.device_found.emit(
            DeviceRecord(
                device_name=socket.gethostname(),
                ip=self.network_info.address,
                mac=self.network_info.local_mac,
                found_at=found_at,
                interface_alias=self.network_info.interface_description or self.network_info.interface_alias,
            )
        )

    def emit_device(self, ip, mac, interface_name=""):
        if ip in self._known_ips:
            return
        self._known_ips.add(ip)
        found_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        device_name = resolve_device_name(ip) if self.resolve_names else "未解析"
        self.device_found.emit(
            DeviceRecord(
                device_name=device_name,
                ip=ip,
                mac=mac,
                found_at=found_at,
                interface_alias=interface_name or self.network_info.interface_description or self.network_info.interface_alias,
            )
        )

    def emit_current_neighbors(self, network):
        found_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        neighbors = load_neighbors()
        for ip, (mac, alias) in sorted(neighbors.items(), key=lambda item: ipaddress.ip_address(item[0])):
            try:
                address = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if address not in network or ip in self._known_ips:
                continue
            self._known_ips.add(ip)
            device_name = resolve_device_name(ip) if self.resolve_names else "未解析"
            self.device_found.emit(
                DeviceRecord(
                    device_name=device_name,
                    ip=ip,
                    mac=mac,
                    found_at=found_at,
                    interface_alias=alias or self.network_info.interface_description or self.network_info.interface_alias,
                )
            )


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("局域网 IP/MAC 扫描器")
        icon_path = resource_path("HX.png")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))
        self.resize(880, 560)
        self.networks = []
        self.worker = None
        self.records = {}
        self.setup_ui()
        self.refresh_networks()

    def setup_ui(self):
        central = QWidget(self)
        root = QVBoxLayout(central)
        root.setContentsMargins(14, 14, 14, 14)
        root.setSpacing(10)

        top_bar = QHBoxLayout()
        top_bar.addWidget(QLabel("扫描网段"))

        self.network_combo = QComboBox()
        self.network_combo.setMinimumWidth(420)
        top_bar.addWidget(self.network_combo, 1)

        self.refresh_button = QPushButton("刷新网段")
        self.refresh_button.clicked.connect(self.refresh_networks)
        top_bar.addWidget(self.refresh_button)

        top_bar.addWidget(QLabel("超时(ms)"))
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(100, 5000)
        self.timeout_spin.setSingleStep(100)
        self.timeout_spin.setValue(300)
        top_bar.addWidget(self.timeout_spin)

        self.resolve_names_checkbox = QCheckBox("解析设备名称")
        self.resolve_names_checkbox.setToolTip("开启后会尝试 DNS/NetBIOS 查询设备名，扫描速度会变慢。")
        self.resolve_names_checkbox.setChecked(False)
        top_bar.addWidget(self.resolve_names_checkbox)

        root.addLayout(top_bar)

        action_bar = QHBoxLayout()
        self.scan_button = QPushButton("开始扫描")
        self.scan_button.clicked.connect(self.start_scan)
        action_bar.addWidget(self.scan_button)

        self.stop_button = QPushButton("停止")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_scan)
        action_bar.addWidget(self.stop_button)

        self.export_button = QPushButton("导出 TXT")
        self.export_button.clicked.connect(self.export_txt)
        action_bar.addWidget(self.export_button)

        self.clear_button = QPushButton("清空结果")
        self.clear_button.clicked.connect(self.clear_results)
        action_bar.addWidget(self.clear_button)
        action_bar.addStretch(1)
        root.addLayout(action_bar)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        root.addWidget(self.progress_bar)

        self.status_label = QLabel("请选择网段后开始扫描")
        root.addWidget(self.status_label)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["设备名称", "IP 地址", "MAC 地址", "发现时间", "网卡"])
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Interactive)
        self.table.setColumnWidth(0, 160)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        root.addWidget(self.table, 1)

        self.setCentralWidget(central)

    def refresh_networks(self):
        current_label = self.network_combo.currentText()
        self.network_combo.clear()
        self.networks = load_networks()
        if not self.networks:
            self.status_label.setText("未检测到可用 IPv4 网段")
            self.scan_button.setEnabled(False)
            return

        for network_info in self.networks:
            self.network_combo.addItem(network_info.label())

        index = self.network_combo.findText(current_label)
        if index >= 0:
            self.network_combo.setCurrentIndex(index)

        self.scan_button.setEnabled(True)
        self.status_label.setText(f"已检测到 {len(self.networks)} 个 IPv4 网段")

    def selected_network(self):
        index = self.network_combo.currentIndex()
        if index < 0 or index >= len(self.networks):
            return None
        return self.networks[index]

    def start_scan(self):
        network_info = self.selected_network()
        if not network_info:
            QMessageBox.warning(self, "无法扫描", "没有可用的扫描网段。")
            return

        host_count = network_info.network.num_addresses - 2
        if host_count > 4096:
            answer = QMessageBox.question(
                self,
                "确认扫描",
                f"{network_info.network} 包含 {host_count} 个可用地址，扫描可能需要较长时间。是否继续？",
                QMessageBox.Yes | QMessageBox.No,
            )
            if answer != QMessageBox.Yes:
                return

        self.clear_results()
        self.progress_bar.setValue(0)
        self.progress_bar.setMaximum(100)
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.refresh_button.setEnabled(False)
        self.network_combo.setEnabled(False)
        self.timeout_spin.setEnabled(False)
        self.resolve_names_checkbox.setEnabled(False)
        self.status_label.setText("正在启动扫描")

        self.worker = ScanWorker(
            network_info,
            self.timeout_spin.value(),
            resolve_names=self.resolve_names_checkbox.isChecked(),
        )
        self.worker.progress_changed.connect(self.on_progress_changed)
        self.worker.status_changed.connect(self.status_label.setText)
        self.worker.device_found.connect(self.add_record)
        self.worker.finished_scan.connect(self.on_scan_finished)
        self.worker.start()

    def stop_scan(self):
        if self.worker:
            self.worker.request_stop()
            self.status_label.setText("正在停止扫描，请稍候")
            self.stop_button.setEnabled(False)

    def on_progress_changed(self, completed, total):
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(completed)
        self.status_label.setText(f"正在扫描：{completed}/{total}")

    def on_scan_finished(self, count):
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.refresh_button.setEnabled(True)
        self.network_combo.setEnabled(True)
        self.timeout_spin.setEnabled(True)
        self.resolve_names_checkbox.setEnabled(True)
        self.status_label.setText(f"扫描完成，共发现 {count} 台设备")
        self.worker = None

    def add_record(self, record):
        self.records[record.ip] = record
        row = self.table.rowCount()
        self.table.insertRow(row)
        row_values = [
            record.device_name,
            record.ip,
            record.mac,
            record.found_at,
            record.interface_alias,
        ]
        for column, value in enumerate(row_values):
            item = QTableWidgetItem(value)
            item.setTextAlignment(Qt.AlignVCenter | Qt.AlignLeft)
            self.table.setItem(row, column, item)
        self.table.sortItems(1, Qt.AscendingOrder)

    def clear_results(self):
        self.records.clear()
        self.table.setRowCount(0)
        self.progress_bar.setValue(0)

    def export_txt(self):
        if not self.records:
            QMessageBox.information(self, "没有数据", "当前没有可导出的扫描结果。")
            return

        default_name = f"lan_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        path, _ = QFileDialog.getSaveFileName(self, "导出 TXT", default_name, "Text Files (*.txt)")
        if not path:
            return
        if not path.lower().endswith(".txt"):
            path += ".txt"

        lines = [
            "局域网 IP/MAC 扫描结果",
            f"导出时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
        ]
        lines.extend(build_aligned_txt(self.records.values()))

        try:
            with open(path, "w", encoding="utf-8-sig") as file:
                file.write("\n".join(lines) + "\n")
        except OSError as exc:
            QMessageBox.critical(self, "导出失败", f"无法写入文件：\n{exc}")
            return

        QMessageBox.information(self, "导出完成", f"已导出到：\n{path}")

    def closeEvent(self, event):
        if self.worker and self.worker.isRunning():
            self.worker.request_stop()
            self.worker.wait(1500)
        event.accept()


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    icon_path = resource_path("HX.png")
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
