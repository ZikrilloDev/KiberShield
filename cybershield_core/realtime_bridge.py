import ctypes
from ctypes import wintypes
import threading
import os

# Windows API uchun kerakli C-konstantalar
FILE_LIST_DIRECTORY = 1
FILE_SHARE_READ = 1
FILE_SHARE_WRITE = 2
FILE_SHARE_DELETE = 4
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000

FILE_NOTIFY_CHANGE_FILE_NAME = 1
FILE_NOTIFY_CHANGE_SIZE = 8

class RealTimeProtector:
    def __init__(self):
        self.kernel32 = ctypes.windll.kernel32 # type: ignore
        # Agar sizda AI risk_engine bo'lsa, shu yerda chaqirasiz:
        # self.risk_engine = RiskEngine()

    def start_monitoring(self, path="C:\\"):
        print(f"[+] CyberShield OS-Level Engine ishga tushdi. ({path} kuzatilmoqda...)")
        
        # Asosiy dastur qotib qolmasligi uchun alohida Thread'da ishlatamiz
        monitor_thread = threading.Thread(target=self._monitor_directory_fast, args=(path,), daemon=True)
        monitor_thread.start()

    def _monitor_directory_fast(self, path):
        """Windows API orqali C++ kabi tezkor kuzatish"""
        hDir = self.kernel32.CreateFileW(
            path,
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None
        )

        if hDir == -1:
            print("[-] Xato: Papkani kuzatib bo'lmadi. Administrator huquqi kerak bo'lishi mumkin.")
            return

        # 32 KB xotira buferi (Memory Buffer)
        buffer = ctypes.create_string_buffer(32 * 1024)
        bytes_returned = wintypes.DWORD()

        while True:
            # TRUE = barcha ichki papkalarni ham kuzatadi (Subtrees)
            result = self.kernel32.ReadDirectoryChangesW(
                hDir,
                buffer,
                ctypes.sizeof(buffer),
                True, 
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE,
                ctypes.byref(bytes_returned),
                None,
                None
            )

            if result:
                offset = 0
                while True:
                    # C-strukturadan ma'lumotlarni Python'ga ajratib olish
                    next_entry_offset = int.from_bytes(buffer[offset : offset+4], byteorder='little')
                    action = int.from_bytes(buffer[offset+4 : offset+8], byteorder='little')
                    name_length = int.from_bytes(buffer[offset+8 : offset+12], byteorder='little')
                    
                    # Fayl nomini o'qish (UTF-16 formatida keladi)
                    name_bytes = buffer[offset+12 : offset+12+name_length]
                    filename = name_bytes.decode('utf-16le')
                    
                    # 1 = Yangi fayl qo'shildi, 3 = Fayl o'zgartirildi
                    if action in [1, 3]:
                        if filename.endswith(('.exe', '.dll', '.bat', '.ps1')):
                            full_path = os.path.join(path, filename)
                            print(f"[!] OS-Level ogohlantirish | Shubhali fayl: {full_path}")
                            # Shu yerda faylni AI ga tekshirishga yuborishingiz mumkin!
                            # self.risk_engine.evaluate(full_path)
                    
                    if next_entry_offset == 0:
                        break
                    offset += next_entry_offset