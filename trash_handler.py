import os
import shutil
from datetime import datetime
from utils.logger import log_event

TRASH_DIR = "quarantine/trash"

def delete_file(filepath, force_delete=False):
    if not os.path.exists(TRASH_DIR):
        os.makedirs(TRASH_DIR)

    if not os.path.exists(filepath):
        log_event(f"[КОРЗИНА] Файл не найден: {filepath}")
        return False

    filename = os.path.basename(filepath)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    trashed_name = f"{filename}_{timestamp}"

    try:
        if force_delete:
            os.remove(filepath)
            log_event(f"[КОРЗИНА] Файл {filename} полностью удалён с диска.")
        else:
            dst = os.path.join(TRASH_DIR, trashed_name)
            shutil.move(filepath, dst)
            log_event(f"[КОРЗИНА] Файл перемещён в trash: {dst}")
        return True

    except Exception as e:
        log_event(f"[КОРЗИНА][ОШИБКА] {filepath}: {e}")
        return False
