#include <windows.h>
#include <iostream>
#include <string>
#include <vector>

void MonitorDirectory(LPCWSTR path) {
    // 1. Papkani to'g'ri huquqlar bilan ochish
    HANDLE hDir = CreateFileW(
        path,
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, // Asinxron operatsiyalar uchun OVERLAPPED shart
        NULL
    );

    if (hDir == INVALID_HANDLE_VALUE) {
        std::cerr << "XATO: Papkani ochib bo'lmadi! Kod: " << GetLastError() << std::endl;
        return;
    }

    // 64KB bufer (Katta hajm xotira to'lib ketishini oldini oladi)
    std::vector<BYTE> buffer(64 * 1024);
    DWORD bytesReturned = 0;

    OVERLAPPED overlapped = { 0 };
    overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    if (overlapped.hEvent == NULL) {
        CloseHandle(hDir);
        return;
    }

    std::wcout << L"INFO|Kuzatuv boshlandi: " << path << std::endl;
    std::wcout.flush(); // Python real-vaqtda o'qishi uchun buferni majburiy tozalash

    while (true) {
        ResetEvent(overlapped.hEvent);

        BOOL success = ReadDirectoryChangesW(
            hDir,
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            TRUE, // Ichki papkalarni ham kuzatish
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE,
            &bytesReturned,
            &overlapped,
            NULL
        );

        if (!success && GetLastError() != ERROR_IO_PENDING) {
            std::cerr << "XATO: ReadDirectoryChangesW muvaffaqiyatsiz bo'ldi. Kod: " << GetLastError() << std::endl;
            break;
        }

        // Event sodir bo'lishini kutish
        DWORD dwWait = WaitForSingleObject(overlapped.hEvent, INFINITE);

        if (dwWait == WAIT_OBJECT_0) {
            if (GetOverlappedResult(hDir, &overlapped, &bytesReturned, FALSE) && bytesReturned > 0) {
                FILE_NOTIFY_INFORMATION* pNotify = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buffer.data());

                do {
                    std::wstring fileName(pNotify->FileName, pNotify->FileNameLength / sizeof(WCHAR));

                    // Action turlari: 1-Yaratildi, 2-O'chirildi, 3-O'zgartirildi, 4-Nomi o'zgartirildi (Eski), 5-Nomi o'zgartirildi (Yangi)
                    std::wcout << pNotify->Action << L"|" << fileName << std::endl;
                    std::wcout.flush(); // GUI orqada qolmasligi uchun darhol uzatish

                    if (pNotify->NextEntryOffset == 0) break;
                    pNotify = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(
                        reinterpret_cast<BYTE*>(pNotify) + pNotify->NextEntryOffset
                    );
                } while (true);
            }
        }
    }

    CloseHandle(overlapped.hEvent);
    CloseHandle(hDir);
}

int main(int argc, char* argv[]) {
    // UTF-8 chiqarishni sozlash
    SetConsoleOutputCP(CP_UTF8);

    std::wstring targetPath = L"C:\\Users"; // Standart xavfsiz papka

    if (argc > 1) {
        int wlen = MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, NULL, 0);
        if (wlen > 0) {
            std::vector<wchar_t> wbuf(wlen);
            MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, wbuf.data(), wlen);
            targetPath = wbuf.data();
        }
    }

    MonitorDirectory(targetPath.c_str());
    return 0;
}