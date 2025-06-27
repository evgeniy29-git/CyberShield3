from html_reporter import generate_report
import os
import subprocess
import time
import psutil
import shutil
from datetime import datetime
from utils.logger import log_event

QUARANTINE_DIR = "quarantine"
DYNAMIC_LOG_DIR = "analysis/dynamic"

def run_in_sandbox(file_path, timeout=5):
    try:
        if not os.path.exists(DYNAMIC_LOG_DIR):
            os.makedirs(DYNAMIC_LOG_DIR)
        try:
            proc = subprocess.Popen(file_path, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            p = psutil.Process(proc.pid)
            log_event(f"[DYNAMIC] Запущен анализ {file_path} (PID {p.pid})")

        except Exception as e:
            log_event(f"[DYNAMIC][ОШИБКА ЗАПУСКА] {file_path}: {e}")

            return


        time.sleep(timeout)

        # ⛓ Фиксируем поведение
        open_files = p.open_files()
        conns = p.connections()
        behavior = []

        if open_files:
            behavior.append(f"Открытые файлы: {[f.path for f in open_files]}")

        for c in conns:
            if c.raddr:
                behavior.append(f"Сетевое соединение: {c.raddr.ip}:{c.raddr.port}")

        # 💾 Сохраняем отчёт
        filename = os.path.basename(file_path)
        log_path = os.path.join(DYNAMIC_LOG_DIR, f"{filename}.log")
        with open(log_path, "w", encoding="utf-8") as f:
            for line in behavior:
                f.write(line + "\n")

        p.terminate()
        log_event(f"[DYNAMIC] Анализ завершён для {filename}. Записано в {log_path}")

    except Exception as e:
        log_event(f"[DYNAMIC][ОШИБКА] {file_path}: {e}")


import pefile
from utils.pe_analyzer import analyze_imports
from utils.pe_analyzer import load_signature_definitions
from utils.hash_tools import get_sha256

signatures = load_signature_definitions()

def analyze_quarantine():
    if not os.path.exists(DYNAMIC_LOG_DIR):
        os.makedirs(DYNAMIC_LOG_DIR)

    for fname in os.listdir(QUARANTINE_DIR):
        full_path = os.path.join(QUARANTINE_DIR, fname)
        if not full_path.endswith(".exe"):
            continue

        # ➤ Поведение
        run_in_sandbox(full_path)
        log_path = os.path.join(DYNAMIC_LOG_DIR, f"{fname}.log")
        behavior = []
        if os.path.exists(log_path):
            with open(log_path, "r", encoding="utf-8") as f:
                behavior = f.readlines()

        # ➤ Статический анализ
        section_hits = []
        import_hits = []
        try:
            pe = pefile.PE(full_path)
            for section in pe.sections:
                data = section.get_data()
                for sig in signatures:
                    if sig["signature_bytes"] in data:
                        section_hits.append({
                            "name": sig["name"],
                            "family": sig["family"]
                        })
            import_hits = analyze_imports(pe)
        except Exception as e:
            log_event(f"[ОШИБКА] Не удалось проанализировать {fname}: {e}")

        if not behavior:
            log_event(f"[DYNAMIC] Поведение не обнаружено для {fname}")

        # ➤ Отчёт
        generate_report(full_path, section_hits, import_hits, behavior)

