#!/usr/bin/env python3
"""
Запуск mitmproxy с подробным логированием и сохранением трафика в файл.
Показывает ошибки, таймауты, connection refused, SSL ошибки в реальном времени.

Использование:
    python capture.py                # сохранит в capture_<дата>.flows
    python capture.py -o mytraffic   # сохранит в mytraffic.flows
    python capture.py -p 9090        # другой порт
    python capture.py --rotate 10    # ротация каждые 10 минут
    python capture.py --rotate-size 50  # ротация каждые 50 MB
    python capture.py --no-sslkey    # без SSLKEYLOGFILE
"""

import subprocess
import sys
import os
from datetime import datetime
import argparse


def main():
    parser = argparse.ArgumentParser(description="Запуск mitmproxy с записью трафика")
    parser.add_argument("-o", "--output", help="Имя выходного файла (без расширения)", default=None)
    parser.add_argument("-p", "--port", type=int, default=8080, help="Порт прокси (по умолчанию 8080)")
    parser.add_argument("--rotate", type=int, default=0, help="Ротация файлов каждые N минут (0 = без ротации)")
    parser.add_argument("--rotate-size", type=int, default=0, help="Ротация файлов каждые N мегабайт (0 = без ротации)")
    parser.add_argument("--no-sslkey", action="store_true", help="Не записывать SSLKEYLOGFILE")
    args = parser.parse_args()

    base_dir = os.path.dirname(os.path.abspath(__file__))

    if args.output:
        base_name = args.output if args.output.endswith(".flows") else f"{args.output}.flows"
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"capture_{ts}.flows"

    flows_path = os.path.join(base_dir, base_name)
    addon_script = os.path.join(base_dir, "_capture_addon.py")

    cmd = [
        "mitmdump",
        "-p", str(args.port),
        "-w", flows_path,
        "-s", addon_script,
        "--set", "console_eventlog_verbosity=debug",
        "--set", "connection_eventlog_verbosity=debug",
    ]

    env = os.environ.copy()

    sslkey_path = os.path.join(base_dir, "sslkeys.log")
    if not args.no_sslkey:
        env["SSLKEYLOGFILE"] = sslkey_path
        print(f"[*] SSL ключи записываются в: {sslkey_path}")
        print(f"[*] Используй в Wireshark: Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log")

    if args.rotate > 0:
        cmd.extend(["--set", f"timer_period={args.rotate * 60}"])
    if args.rotate_size > 0:
        cmd.extend(["--set", f"stream_large_bodies={args.rotate_size}m"])

    print(f"[*] Запуск mitmproxy на порту {args.port}")
    print(f"[*] Трафик сохраняется в: {flows_path}")
    print(f"[*] Настройте прокси на localhost:{args.port}")
    if args.rotate > 0:
        print(f"[*] Ротация файлов: каждые {args.rotate} минут")
    if args.rotate_size > 0:
        print(f"[*] Ротация по размеру: каждые {args.rotate_size} MB")
    print(f"[*] Для остановки нажмите Ctrl+C")
    print(f"[*] Логи ошибок и таймаутов отображаются ниже:")
    print("=" * 60)

    try:
        subprocess.run(cmd, check=True, env=env)
    except KeyboardInterrupt:
        print(f"\n{'=' * 60}")
        print(f"[*] Остановлен. Трафик сохранён в: {flows_path}")
        if not args.no_sslkey and os.path.exists(sslkey_path):
            print(f"[*] SSL ключи: {sslkey_path}")
    except FileNotFoundError:
        print("[!] mitmproxy не найден. Установите: pip install mitmproxy")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"[!] Ошибка mitmproxy (код {e.returncode}): {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
