import os
import urllib.request
import zipfile
import shutil

WINDIVERT_VERSION = "2.2.2"
LIBS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "libs")

def get_windivert_header():
    header_file = os.path.join(LIBS_DIR, "WinDivert.h")
    
    if os.path.exists(header_file):
        print("[+] WinDivert.h уже есть.")
        return True

    print("[!] Скачиваю WinDivert для извлечения .h файла...")
    url = f"https://github.com/basil00/Divert/releases/download/v{WINDIVERT_VERSION}/WinDivert-{WINDIVERT_VERSION}-A.zip"
    zip_path = os.path.join(LIBS_DIR, "temp_wd.zip")
    temp_extract = os.path.join(LIBS_DIR, "wd_temp")

    try:
        urllib.request.urlretrieve(url, zip_path)
        print("[+] Скачано. Распаковка...")
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(temp_extract)
        
        os.remove(zip_path)

        # Ищем WinDivert.h по всему архиву
        import glob
        found = glob.glob(os.path.join(temp_extract, "**", "WinDivert.h"), recursive=True)
        
        if found:
            shutil.copy2(found[0], header_file)
            print(f"[+] WinDivert.h успешно скопирован.")
            print(f"[*] Путь: {header_file}")
        else:
            print("[-] WinDivert.h не найден в архиве.")
            shutil.rmtree(temp_extract)
            return False

        shutil.rmtree(temp_extract)
        return True

    except Exception as e:
        print(f"[-] Ошибка: {e}")
        if os.path.exists(zip_path):
            os.remove(zip_path)
        if os.path.exists(temp_extract):
            shutil.rmtree(temp_extract)
        return False

if __name__ == "__main__":
    os.makedirs(LIBS_DIR, exist_ok=True)
    get_windivert_header()