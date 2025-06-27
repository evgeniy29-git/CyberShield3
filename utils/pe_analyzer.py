import json

def load_signature_definitions(path="signatures.json"):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            # Конвертируем строку в байты
            for entry in data:
                entry["signature_bytes"] = bytes(entry["signature"].encode("utf-8").decode("unicode_escape"), "latin1")
            return data
    except Exception as e:
        return []

def analyze_imports(pe):
    suspicious = []
    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        return suspicious

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if imp.name:
                name = imp.name.decode().lower()
                if name in ["virtualallocex", "createremotethread", "writeprocessmemory", "loadlibrarya", "winexec"]:
                    suspicious.append(name)
    return suspicious
