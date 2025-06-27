import os
import re
from datetime import datetime

REPORT_DIR = "analysis/reports"
OUTPUT_INDEX = os.path.join(REPORT_DIR, "index.html")

def create_summary_index():
    rows = []

    for fname in os.listdir(REPORT_DIR):
        if fname.startswith("report_") and fname.endswith(".html"):
            path = os.path.join(REPORT_DIR, fname)
            sample_name = fname.replace("report_", "")
            full_report = os.path.join("reports", fname)

            # Попробуем извлечь уровень угрозы по имени файла (опционально)
            severity = "⚪"  # По умолчанию — не классифицирован
            if "high" in fname.lower():
                severity = "🔴"
            elif "med" in fname.lower():
                severity = "🟡"
            elif "low" in fname.lower():
                severity = "🟢"

            rows.append(f"""
                <tr>
                    <td>{sample_name}</td>
                    <td><a href="{full_report}" target="_blank">Открыть</a></td>
                    <td style="font-size: 20px;">{severity}</td>
                </tr>
            """)

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Отчёты анализа</title>
        <style>
            body {{ font-family: Arial; background-color: #f5f5f5; padding: 20px; }}
            table {{ background: white; border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
            th {{ background-color: #eee; }}
            h1 {{ margin-bottom: 20px; }}
        </style>
    </head>
    <body>
        <h1>Сводный отчёт по анализу файлов ({datetime.now().strftime("%Y-%m-%d %H:%M")})</h1>
        <table>
            <tr>
                <th>Файл</th>
                <th>Отчёт</th>
                <th>Статус</th>
            </tr>
            {''.join(rows)}
        </table>
    </body>
    </html>
    """

    with open(OUTPUT_INDEX, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[✓] Сводный отчёт создан: {OUTPUT_INDEX}")

import webbrowser
webbrowser.open(OUTPUT_INDEX)
