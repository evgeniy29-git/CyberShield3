import psutil
from utils.logger import log_event

def analyze_behavior(proc):
    try:
        # 📁 Файлы, открытые процессом
        files = proc.open_files()
        if files:
            file_paths = [f.path for f in files]
            log_event(f"[ПОВЕДЕНИЕ] {proc.name()} (PID {proc.pid}) открыл файлы: {file_paths}")

        # 🌐 Сетевые соединения
        conns = proc.connections(kind='inet')
        for conn in conns:
            if conn.raddr:
                log_event(f"[ПОВЕДЕНИЕ] {proc.name()} (PID {proc.pid}) установил соединение с {conn.raddr.ip}:{conn.raddr.port}")


    except Exception as e:
        log_event(f"[ПОВЕДЕНИЕ] Ошибка при анализе поведения PID {proc.pid}: {e}")
