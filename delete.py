from trash_handler import delete_file

# Только переместить в корзину
delete_file("quarantine/suspect.exe", force_delete=False)

# Удалить с диска
delete_file("quarantine/backdoor.exe", force_delete=True)
