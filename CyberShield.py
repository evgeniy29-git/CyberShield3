import tkinter as tk
from tkinter import filedialog, messagebox
import webbrowser
from trash_handler import delete_file
from html_reporter import generate_report
from analysis.sanbox_executor import run_in_sandbox
from utils.pe_analyzer import load_signature_definitions, analyze_imports
import pefile, os

signatures = load_signature_definitions()

class AntivirusGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ MiniAV GUI")

        self.file_path = tk.StringVar()
        self.log_text = tk.Text(root, height=10, width=80)
        self.setup_ui()

    def setup_ui(self):
        tk.Button(text="📁 Выбрать файл", command=self.select_file).pack(pady=5)
        tk.Entry(textvariable=self.file_path, width=80).pack()

        tk.Button(text="🔬 Сканировать и создать отчёт", command=self.scan_file).pack(pady=5)
        tk.Button(text="📄 Открыть отчёт", command=self.open_report).pack(pady=5)
        tk.Button(text="🧹 Удалить файл с диска", command=self.delete_sample).pack(pady=5)
        tk.Button(text="📊 Открыть сводку (index.html)", command=self.open_index).pack(pady=5)

        tk.Label(text="Лог:").pack()
        self.log_text.pack()

    def log(self, msg):
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)

    def select_file(self):
        path = filedialog.askopenfilename(filetypes=[("EXE files", "*.exe")])
        if path:
            self.file_path.set(path)

    def scan_file(self):
        path = self.file_path.get()
        if not path or not os.path.exists(path):
            self.log("❗ Файл не выбран или не существует")
            return

        self.log(f"📥 Сканирую: {path}")
        run_in_sandbox(path)

        section_hits = []
        import_hits = []

        try:
            pe = pefile.PE(path)
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
            self.log(f"❌ Ошибка анализа: {e}")

        # Поведение читается из sandbox
        log_path = os.path.join("analysis/dynamic", os.path.basename(path) + ".log")
        behavior = []
        if os.path.exists(log_path):
            with open(log_path, "r", encoding="utf-8") as f:
                behavior = f.readlines()

        generate_report(path, section_hits, import_hits, behavior)
        self.log("✅ Отчёт создан.")

    def open_report(self):
        path = self.file_path.get()
        if not path:
            return
        html = os.path.join("analysis/reports", f"report_{os.path.basename(path)}.html")
        if os.path.exists(html):
            webbrowser.open(f"file://{os.path.abspath(html)}")
        else:
            self.log("❗ Отчёт не найден")

    def open_index(self):
        index = os.path.join("analysis/reports", "index.html")
        if os.path.exists(index):
            webbrowser.open(f"file://{os.path.abspath(index)}")
        else:
            self.log("❗ index.html не найден")

    def delete_sample(self):
        path = self.file_path.get()
        if not path:
            return
        confirm = messagebox.askyesno("Удаление", f"Удалить {os.path.basename(path)} с диска?")
        if confirm:
            deleted = delete_file(path, force_delete=True)
            if deleted:
                self.log("🧹 Файл удалён.")
            else:
                self.log("❗ Ошибка удаления.")

if __name__ == "__main__":
    root = tk.Tk()
    app = AntivirusGUI(root)
    root.mainloop()
