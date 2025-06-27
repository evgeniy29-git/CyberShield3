import os
import pefile
import json
from jinja2 import Environment, FileSystemLoader
from datetime import datetime
from utils.hash_tools import get_sha256

TEMPLATE_DIR = "templates"
REPORT_DIR = "analysis/reports"
DYNAMIC_LOG_DIR = "analysis/dynamic"
QUARANTINE_DIR = "quarantine"

env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))

def generate_report(exe_path, signatures, imports, behavior_lines):
    if not os.path.exists(REPORT_DIR):
        os.makedirs(REPORT_DIR)

    sha256 = get_sha256(exe_path)
    filename = os.path.basename(exe_path)
    template = env.get_template("report_template.html")

    rendered = template.render(
        filename=filename,
        sha256=sha256,
        path=exe_path,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        signatures=signatures,
        imports=imports,
        behavior="\n".join(behavior_lines) if behavior_lines else None
    )

    report_path = os.path.join(REPORT_DIR, f"report_{filename}.html")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(rendered)
