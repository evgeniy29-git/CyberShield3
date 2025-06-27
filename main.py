from core.process_monitor import monitor_processes

if __name__ == "__main__":
    monitor_processes()

from utils.report_indexer import create_summary_index

# После генерации всех отчётов:
create_summary_index()


