#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <cstdint>
#include <iomanip>

// Yordamchi funksiya: Berilgan PID bo'yicha jarayon nomini olish
std::string GetProcessName(DWORD pid) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return "";
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    std::string name;
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                name = pe.szExeFile;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return name;
}

// Yordamchi funksiya: Berilgan PID uchun asosiy modul (asosiy .exe) manzil oralig'ini olish
bool GetProcessMainModuleRange(DWORD pid, uintptr_t& start, uintptr_t& end) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32 me;
    me.dwSize = sizeof(MODULEENTRY32);
    bool found = false;
    if (Module32First(hSnapshot, &me)) {
        do {
            if (me.th32ProcessID == pid) {
                start = reinterpret_cast<uintptr_t>(me.modBaseAddr);
                end = start + me.modBaseSize;
                found = true;
                break;
            }
        } while (Module32Next(hSnapshot, &me));
    }
    CloseHandle(hSnapshot);
    return found;
}

// Asosiy skanerlash va patching funksiyasi
bool ScanAndPatchMemory(DWORD pid, const std::vector<uint8_t>& pattern, const std::vector<uint8_t>& replace) {
    if (pattern.empty()) {
        std::cerr << "[!] Pattern bo'sh bo'lmasligi kerak.\n";
        return false;
    }
    if (replace.size() != pattern.size()) {
        std::cerr << "[!] Almashtiriladigan qiymat pattern bilan bir xil uzunlikda bo'lishi shart.\n";
        return false;
    }

    // 1. Jarayonga ulanish (PROCESS_ALL_ACCESS so'raladi)
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "[!] OpenProcess muvaffaqiyatsiz. Kod: " << GetLastError()
                  << "\n    Administrator sifatida ishga tushiring yoki jarayon himoyalangan bo'lishi mumkin.\n";
        return false;
    }
    std::cout << "[+] Jarayonga tutqich ochildi. PID: " << pid
              << " (" << GetProcessName(pid) << ")\n";

    // Jarayonning asosiy modul oralig'i (ixtiyoriy - faqat asosiy exe ichida qidirish uchun)
    uintptr_t mainStart = 0, mainEnd = 0;
    bool restrictToMainModule = false; // Agar true qilinsa, faqat asosiy modul skanerlanadi
    if (restrictToMainModule) {
        if (GetProcessMainModuleRange(pid, mainStart, mainEnd)) {
            std::cout << "[*] Faqat asosiy modul skanerlanadi: 0x"
                      << std::hex << mainStart << " - 0x" << mainEnd << std::dec << "\n";
        } else {
            std::cerr << "[!] Asosiy modul topilmadi, to'liq skanerlanadi.\n";
            restrictToMainModule = false;
        }
    }

    // 2. Xotira sahifalarini kezish
    uintptr_t address = 0;
    MEMORY_BASIC_INFORMATION mbi;
    bool foundAndPatched = false;
    size_t patchCount = 0;

    while (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi))) {
        // Agar faqat asosiy modulda qidirsak, chegaradan tashqarida bo'lsa, to'xtatamiz
        if (restrictToMainModule) {
            if (address >= mainEnd) break;
            if (address + mbi.RegionSize < mainStart) {
                address += mbi.RegionSize;
                continue;
            }
        }

        // Himoya bayroqlarini tekshirish: o'qish va yozishga ruxsat etilgan bo'lishi kerak
        bool isReadable = (mbi.State == MEM_COMMIT) &&
                          (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE));
        // Yozishga ruxsatni keyinroq VirtualProtectEx bilan ta'minlaymiz, lekin o'qish uchun faqat o'qiladigan sahifalar kerak
        if (!isReadable || mbi.State != MEM_COMMIT) {
            address += mbi.RegionSize;
            continue;
        }

        // Sahifani mahalliy buferga o'qib olamiz
        std::vector<uint8_t> buffer(mbi.RegionSize);
        SIZE_T bytesRead;
        if (!ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead)) {
            // Ba'zi sahifalar o'qishga ruxsat berilgan bo'lsa ham, ReadProcessMemory xatolik berishi mumkin
            address += mbi.RegionSize;
            continue;
        }
        buffer.resize(bytesRead);

        // Pattern qidirish (oddiy substring qidiruv)
        auto it = buffer.begin();
        while ((it = std::search(it, buffer.end(), pattern.begin(), pattern.end())) != buffer.end()) {
            // Xotiradagi mutlaq manzilni hisoblash
            uintptr_t foundAddress = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + (it - buffer.begin());
            std::cout << "[+] Pattern topildi: 0x" << std::hex << foundAddress << std::dec << "\n";

            // 4. Himoyani o'zgartirish va yozish
            DWORD oldProtect;
            if (!VirtualProtectEx(hProcess, reinterpret_cast<LPVOID>(foundAddress), replace.size(), PAGE_READWRITE, &oldProtect)) {
                std::cerr << "[!] VirtualProtectEx muvaffaqiyatsiz. Kod: " << GetLastError() << "\n";
                ++it;
                continue;
            }

            // Yangi qiymatni yozish
            SIZE_T bytesWritten;
            if (WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(foundAddress), replace.data(), replace.size(), &bytesWritten) &&
                bytesWritten == replace.size()) {
                std::cout << "    -> Muvaffaqiyatli almashtirildi (" << replace.size() << " bayt).\n";
                patchCount++;
                foundAndPatched = true;
            } else {
                std::cerr << "    -> WriteProcessMemory xatosi. Kod: " << GetLastError() << "\n";
            }

            // Himoyani avvalgi holatiga qaytarish
            DWORD dummy;
            VirtualProtectEx(hProcess, reinterpret_cast<LPVOID>(foundAddress), replace.size(), oldProtect, &dummy);

            ++it;
        }

        address += mbi.RegionSize;
    }

    CloseHandle(hProcess);
    std::cout << "[*] Skanerlash yakunlandi. " << patchCount << " ta joy almashtirildi.\n";
    return foundAndPatched;
}

// Yordamchi: Stringni hexdump yoki oddiy matn sifatida vektorga o'tkazish
std::vector<uint8_t> ParsePattern(const std::string& input) {
    std::vector<uint8_t> bytes;
    if (input.empty()) return bytes;

    // Agar "0x" bilan boshlansa yoki bo'shliqlar bo'lsa, hex format deb qabul qilamiz
    bool isHex = (input.find("0x") == 0) || (input.find(' ') != std::string::npos);
    if (isHex) {
        std::string cleaned;
        for (char c : input) {
            if (c != ' ' && c != '0' && c != 'x' && c != 'X' && c != ',')
                cleaned += c;
        }
        if (cleaned.size() % 2 != 0) {
            std::cerr << "[!] Hex string juft uzunlikda bo'lishi kerak.\n";
            return {};
        }
        for (size_t i = 0; i < cleaned.size(); i += 2) {
            std::string byteStr = cleaned.substr(i, 2);
            uint8_t byte = static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16));
            bytes.push_back(byte);
        }
    } else {
        // Oddiy matn
        bytes.assign(input.begin(), input.end());
    }
    return bytes;
}

int main(int argc, char* argv[]) {
    std::cout << "=== Phantom-Mem: Polymorphic Memory Scanner & Patcher ===\n\n";

    if (argc < 4) {
        std::cerr << "Foydalanish:\n"
                  << "  " << argv[0] << " <PID> <pattern> <replace>\n"
                  << "Misol (matn):\n"
                  << "  " << argv[0] << " 1234 \"Hello\" \"World\"\n"
                  << "Misol (hex):\n"
                  << "  " << argv[0] << " 1234 \"48 65 6C 6C 6F\" \"57 6F 72 6C 64\"\n";
        return 1;
    }

    DWORD pid = std::stoul(argv[1]);
    std::string patternStr = argv[2];
    std::string replaceStr = argv[3];

    std::vector<uint8_t> pattern = ParsePattern(patternStr);
    std::vector<uint8_t> replace = ParsePattern(replaceStr);

    if (pattern.empty() || replace.empty()) {
        std::cerr << "[!] Pattern yoki replace qiymat noto'g'ri.\n";
        return 1;
    }

    std::cout << "[*] PID: " << pid << "\n";
    std::cout << "[*] Pattern (bayt): ";
    for (auto b : pattern) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b << " ";
    std::cout << std::dec << "\n";
    std::cout << "[*] Yangi qiymat (bayt): ";
    for (auto b : replace) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b << " ";
    std::cout << std::dec << "\n\n";

    if (ScanAndPatchMemory(pid, pattern, replace)) {
        std::cout << "\n[+] Operatsiya muvaffaqiyatli yakunlandi.\n";
    } else {
        std::cout << "\n[-] Pattern topilmadi yoki xatolik yuz berdi.\n";
    }

    return 0;
}
