#!/usr/bin/env python3
"""Управление системным прокси в Windows (WinINET + WinHTTP)."""

from __future__ import annotations

import argparse
import ctypes
import json
import platform
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

CONFIG_PATH = Path(__file__).with_name("proxy_settings.json")
BACKUP_PATH = Path(__file__).with_name("proxy_backup.json")
RUN_KEY = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
RUN_VALUE_NAME = "ProxiWindowsAutoApply"
INTERNET_SETTINGS_KEY = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"


@dataclass
class ProxySettings:
    host: str = "127.0.0.1"
    port: int = 1080
    protocol: str = "http"  # http | socks5
    bypass: str = "localhost;127.*;10.*;172.16.*;192.168.*;<local>"

    @property
    def server(self) -> str:
        return f"{self.host}:{self.port}"

    @property
    def wininet_proxy_server(self) -> str:
        if self.protocol == "socks5":
            return f"socks={self.server};http={self.server};https={self.server}"
        return f"http={self.server};https={self.server};ftp={self.server}"


@dataclass
class ProxyBackup:
    proxy_enable: str | None = None
    proxy_server: str | None = None
    proxy_override: str | None = None
    winhttp_mode: str = "direct"
    winhttp_proxy: str | None = None
    winhttp_bypass: str | None = None


def is_windows() -> bool:
    return platform.system().lower() == "windows"


def is_admin() -> bool:
    if not is_windows():
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run_command(command: list[str]) -> tuple[bool, str]:
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        output = (result.stdout + "\n" + result.stderr).strip()
        return result.returncode == 0, output
    except Exception as exc:
        return False, str(exc)


def read_reg_value(name: str) -> str | None:
    ok, out = run_command(["reg", "query", INTERNET_SETTINGS_KEY, "/v", name])
    if not ok:
        return None
    match = re.search(rf"{re.escape(name)}\s+REG_\w+\s+(.+)", out)
    return match.group(1).strip() if match else None


def notify_internet_settings_changed() -> None:
    if not is_windows():
        return
    try:
        internet_set_option = ctypes.windll.wininet.InternetSetOptionW
        internet_set_option(0, 39, 0, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
        internet_set_option(0, 37, 0, 0)  # INTERNET_OPTION_REFRESH
    except Exception:
        pass


def save_settings(settings: ProxySettings) -> None:
    CONFIG_PATH.write_text(json.dumps(asdict(settings), ensure_ascii=False, indent=2), encoding="utf-8")


def load_settings() -> ProxySettings:
    if not CONFIG_PATH.exists():
        settings = ProxySettings()
        save_settings(settings)
        return settings

    raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    protocol = str(raw.get("protocol", "http")).lower()
    if protocol not in {"http", "socks5"}:
        protocol = "http"
    return ProxySettings(
        host=str(raw.get("host", "127.0.0.1")),
        port=int(raw.get("port", 1080)),
        protocol=protocol,
        bypass=str(raw.get("bypass", "localhost;127.*;<local>")),
    )


def save_backup(backup: ProxyBackup) -> None:
    BACKUP_PATH.write_text(json.dumps(asdict(backup), ensure_ascii=False, indent=2), encoding="utf-8")


def load_backup() -> ProxyBackup | None:
    if not BACKUP_PATH.exists():
        return None
    raw = json.loads(BACKUP_PATH.read_text(encoding="utf-8"))
    return ProxyBackup(
        proxy_enable=raw.get("proxy_enable"),
        proxy_server=raw.get("proxy_server"),
        proxy_override=raw.get("proxy_override"),
        winhttp_mode=raw.get("winhttp_mode", "direct"),
        winhttp_proxy=raw.get("winhttp_proxy"),
        winhttp_bypass=raw.get("winhttp_bypass"),
    )


def create_backup() -> tuple[bool, str]:
    proxy_enable = read_reg_value("ProxyEnable")
    proxy_server = read_reg_value("ProxyServer")
    proxy_override = read_reg_value("ProxyOverride")

    ok_http, out_http = run_command(["netsh", "winhttp", "show", "proxy"])
    winhttp_mode = "direct"
    winhttp_proxy = None
    winhttp_bypass = None

    if ok_http:
        if "Direct access" in out_http or "Прямой доступ" in out_http:
            winhttp_mode = "direct"
        else:
            winhttp_mode = "proxy"
            match_proxy = re.search(r"Proxy Server\(s\)\s*:\s*(.+)", out_http)
            match_bypass = re.search(r"Bypass List\s*:\s*(.+)", out_http)
            if match_proxy:
                winhttp_proxy = match_proxy.group(1).strip()
            if match_bypass:
                winhttp_bypass = match_bypass.group(1).strip()

    save_backup(
        ProxyBackup(
            proxy_enable=proxy_enable,
            proxy_server=proxy_server,
            proxy_override=proxy_override,
            winhttp_mode=winhttp_mode,
            winhttp_proxy=winhttp_proxy,
            winhttp_bypass=winhttp_bypass,
        )
    )
    return True, f"Резервная копия сохранена: {BACKUP_PATH.name}"


def configure_settings(settings: ProxySettings) -> ProxySettings:
    print("\n=== Настройка прокси ===")
    host = input(f"Адрес прокси [{settings.host}]: ").strip() or settings.host
    port_value = input(f"Порт прокси [{settings.port}]: ").strip()
    protocol_value = input(f"Протокол (http/socks5) [{settings.protocol}]: ").strip().lower()
    bypass = input(f"Исключения (bypass) [{settings.bypass}]: ").strip() or settings.bypass

    if port_value:
        try:
            port = int(port_value)
            if not (1 <= port <= 65535):
                raise ValueError
        except ValueError:
            print("❌ Неверный порт, оставляю текущий.")
            port = settings.port
    else:
        port = settings.port

    protocol = protocol_value if protocol_value in {"http", "socks5"} else settings.protocol
    if protocol_value and protocol_value not in {"http", "socks5"}:
        print("⚠️ Неверный протокол, оставляю текущий.")

    updated = ProxySettings(host=host, port=port, protocol=protocol, bypass=bypass)
    save_settings(updated)
    print(f"✅ Сохранено: {updated.protocol}://{updated.server}")
    return updated


def set_wininet_proxy(settings: ProxySettings, enabled: bool) -> tuple[bool, str]:
    if enabled:
        ok1, out1 = run_command(
            ["reg", "add", INTERNET_SETTINGS_KEY, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f"]
        )
        ok2, out2 = run_command(
            [
                "reg",
                "add",
                INTERNET_SETTINGS_KEY,
                "/v",
                "ProxyServer",
                "/t",
                "REG_SZ",
                "/d",
                settings.wininet_proxy_server,
                "/f",
            ]
        )
        ok3, out3 = run_command(
            ["reg", "add", INTERNET_SETTINGS_KEY, "/v", "ProxyOverride", "/t", "REG_SZ", "/d", settings.bypass, "/f"]
        )
        notify_internet_settings_changed()
        return ok1 and ok2 and ok3, "\n".join([out1, out2, out3]).strip()

    ok, out = run_command(
        ["reg", "add", INTERNET_SETTINGS_KEY, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f"]
    )
    notify_internet_settings_changed()
    return ok, out


def set_winhttp_proxy(settings: ProxySettings, enabled: bool) -> tuple[bool, str]:
    if enabled:
        return run_command(["netsh", "winhttp", "set", "proxy", settings.server, settings.bypass])
    return run_command(["netsh", "winhttp", "reset", "proxy"])


def apply_proxy(settings: ProxySettings, enabled: bool, silent: bool = False) -> bool:
    if enabled:
        create_backup()

    action = "включаю" if enabled else "отключаю"
    if not silent:
        print(f"\n=== {action.capitalize()} системный прокси ===")

    ok_inet, out_inet = set_wininet_proxy(settings, enabled)
    ok_http, out_http = set_winhttp_proxy(settings, enabled)

    if not silent:
        print("WinINET:", "✅" if ok_inet else "❌")
        if out_inet:
            print(out_inet)

        if not is_admin() and not ok_http:
            print("WinHTTP: ⚠️ (нужны права администратора)")
        else:
            print("WinHTTP:", "✅" if ok_http else "❌")
        if out_http:
            print(out_http)

        if settings.protocol == "socks5" and enabled:
            print("⚠️ WinHTTP не поддерживает SOCKS напрямую; для служб лучше HTTP-прокси.")

    return ok_inet and (ok_http or not is_admin())


def restore_from_backup() -> tuple[bool, str]:
    backup = load_backup()
    if not backup:
        return False, "Резервная копия не найдена."

    if backup.proxy_enable is not None:
        run_command(
            ["reg", "add", INTERNET_SETTINGS_KEY, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", backup.proxy_enable, "/f"]
        )
    if backup.proxy_server is not None:
        run_command(
            ["reg", "add", INTERNET_SETTINGS_KEY, "/v", "ProxyServer", "/t", "REG_SZ", "/d", backup.proxy_server, "/f"]
        )
    if backup.proxy_override is not None:
        run_command(
            ["reg", "add", INTERNET_SETTINGS_KEY, "/v", "ProxyOverride", "/t", "REG_SZ", "/d", backup.proxy_override, "/f"]
        )

    if backup.winhttp_mode == "proxy" and backup.winhttp_proxy:
        cmd = ["netsh", "winhttp", "set", "proxy", backup.winhttp_proxy]
        if backup.winhttp_bypass:
            cmd.append(backup.winhttp_bypass)
        run_command(cmd)
    else:
        run_command(["netsh", "winhttp", "reset", "proxy"])

    notify_internet_settings_changed()
    return True, "Системные настройки восстановлены из резервной копии."


def set_autostart(enabled: bool) -> tuple[bool, str]:
    script_path = Path(__file__).resolve()
    command = f'python "{script_path}" --enable-silent'

    if enabled:
        return run_command(["reg", "add", RUN_KEY, "/v", RUN_VALUE_NAME, "/t", "REG_SZ", "/d", command, "/f"])
    return run_command(["reg", "delete", RUN_KEY, "/v", RUN_VALUE_NAME, "/f"])


def show_status(settings: ProxySettings) -> None:
    print("\n=== Текущий профиль ===")
    print(f"Прокси-сервер: {settings.protocol}://{settings.server}")
    print(f"WinINET string: {settings.wininet_proxy_server}")
    print(f"Исключения:     {settings.bypass}")
    print(f"OS:             {platform.platform()}")
    print(f"Админ:          {'да' if is_admin() else 'нет'}")

    ok_inet, out_inet = run_command(["reg", "query", INTERNET_SETTINGS_KEY, "/v", "ProxyEnable"])
    print("\nWinINET (ProxyEnable):", "✅" if ok_inet else "❌")
    if out_inet:
        print(out_inet)

    ok_http, out_http = run_command(["netsh", "winhttp", "show", "proxy"])
    print("\nWinHTTP:", "✅" if ok_http else "❌")
    if out_http:
        print(out_http)

    ok_run, out_run = run_command(["reg", "query", RUN_KEY, "/v", RUN_VALUE_NAME])
    print("\nАвтозапуск:", "✅ включен" if ok_run else "❌ выключен")
    if ok_run and out_run:
        print(out_run)


def print_menu() -> None:
    print(
        """
================ ПРОКСИ-МЕНЮ ================
1) Настроить прокси (адрес/порт/протокол/исключения)
2) Включить прокси для всего Windows
3) Отключить прокси
4) Показать статус
5) Восстановить из backup
6) Включить автозапуск (применять при входе)
7) Выключить автозапуск
8) Выход
=============================================
"""
    )


def run_cli_mode(args: argparse.Namespace, settings: ProxySettings) -> bool:
    if args.enable:
        return apply_proxy(settings, enabled=True)
    if args.disable:
        return apply_proxy(settings, enabled=False)
    if args.status:
        show_status(settings)
        return True
    if args.enable_silent:
        return apply_proxy(settings, enabled=True, silent=True)
    return False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Управление системным прокси Windows")
    parser.add_argument("--enable", action="store_true", help="Включить прокси")
    parser.add_argument("--disable", action="store_true", help="Отключить прокси")
    parser.add_argument("--status", action="store_true", help="Показать статус")
    parser.add_argument("--enable-silent", action="store_true", help="Тихо включить прокси (для автозапуска)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if not is_windows():
        print("❌ Этот скрипт предназначен для Windows.")
        return

    settings = load_settings()

    if run_cli_mode(args, settings):
        return

    while True:
        print_menu()
        choice = input("Выберите действие: ").strip()

        if choice == "1":
            settings = configure_settings(settings)
        elif choice == "2":
            apply_proxy(settings, enabled=True)
        elif choice == "3":
            apply_proxy(settings, enabled=False)
        elif choice == "4":
            show_status(settings)
        elif choice == "5":
            ok, msg = restore_from_backup()
            print(("✅ " if ok else "❌ ") + msg)
        elif choice == "6":
            ok, out = set_autostart(True)
            print("✅ Автозапуск включён" if ok else "❌ Не удалось включить автозапуск")
            if out:
                print(out)
        elif choice == "7":
            ok, out = set_autostart(False)
            print("✅ Автозапуск выключен" if ok else "❌ Не удалось выключить автозапуск")
            if out:
                print(out)
        elif choice == "8":
            print("До встречи 👋")
            return
        else:
            print("❌ Неизвестный пункт меню")


if __name__ == "__main__":
    main()
