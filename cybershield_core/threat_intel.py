import requests
import hashlib

VT_API_KEY = "SIZNING_VIRUSTOTAL_API_KALITINGIZ" # Bepul olish mumkin

def get_file_hash(filepath):
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as afile:
        buf = afile.read(65536)
        while len(buf) > 0:
            hasher.update(buf)
            buf = afile.read(65536)
    return hasher.hexdigest()

def check_file_global(filepath):
    """Faylni butunjahon bazasidan tekshirish"""
    file_hash = get_file_hash(filepath)
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            malicious_count = stats['malicious']
            
            if malicious_count > 0:
                print(f"[!] DIQQAT: Bu faylni {malicious_count} ta antivirus virus deb topgan!")
                return True
            else:
                print("[+] Global bazada fayl toza.")
                return False
        else:
            print("[-] Fayl global bazada topilmadi, Local AI ga yuboriladi.")
            return None
    except Exception as e:
        print(f"Xato: {e}")
        return None