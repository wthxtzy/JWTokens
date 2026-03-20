#include <iostream>
#include <string>
#include <windows.h> 
#include <algorithm>

extern "C" void GenerateToken(const char* parameters, const char* secret_key, char* out_buffer, int buffer_size);


std::string ConvertConsoleInputToUTF8(const std::string& input) {
    if (input.empty()) return "";
    UINT console_cp = GetConsoleCP();
    int wsize = MultiByteToWideChar(console_cp, 0, input.data(), (int)input.size(), NULL, 0);
    std::wstring wstr(wsize, 0);
    MultiByteToWideChar(console_cp, 0, input.data(), (int)input.size(), &wstr[0], wsize);
    int utf8_size = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string utf8_str(utf8_size, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), &utf8_str[0], utf8_size, NULL, NULL);
    return utf8_str;
}


std::string Minify(std::string str) {
    std::string result;
    for (char c : str) {
        if (c != ' ' && c != '\n' && c != '\r' && c != '\t') {
            result += c;
        }
    }
    return result;
}

int main() {
    SetConsoleOutputCP(CP_UTF8);

    std::string secret_key = "oMtcctQzqo3jpFIL9B8qVwTgGBmfzFb2";

    std::cout << "=== PRO JWT GENERATOR (МНОГОСТРОЧНЫЙ ВВОД) ===" << std::endl;
    std::cout << "Секретный ключ по умолчанию: " << secret_key << std::endl;

    
    std::cout << "\n1. ВСТАВЬТЕ JSON (Payload) И НАЖМИТЕ ENTER ДВАЖДЫ ДЛЯ ЗАВЕРШЕНИЯ:" << std::endl;
    std::cout << "------------------------------------------------------------" << std::endl;

    std::string full_input = "";
    std::string line;

    
    while (std::getline(std::cin, line) && !line.empty()) {
        full_input += line;
    }

   
    std::string clean_payload = Minify(ConvertConsoleInputToUTF8(full_input));

    if (clean_payload.empty()) {
        std::cout << "[!] Ввод пуст. Попробуйте еще раз." << std::endl;
        return 0;
    }

    std::cout << "\n[ИНФО] Данные минифицированы в: " << clean_payload << std::endl;

    char out_buffer[1024] = { 0 };
    GenerateToken(clean_payload.c_str(), secret_key.c_str(), out_buffer, 1024);

    std::cout << "\n--- РЕЗУЛЬТАТ (JWT TOKEN) ---" << std::endl;
    std::cout << out_buffer << std::endl;

    std::cout << "\nНажмите Enter для выхода..." << std::endl;
    std::cin.get();
    return 0;
}