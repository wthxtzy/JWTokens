#include <iostream>
#include <string>
#include <windows.h> 
#include <clocale>
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

int main() {
    setlocale(LC_ALL, "ru_RU.UTF-8");
    SetConsoleOutputCP(CP_UTF8);

    std::string secret = "SecretKeyZMI";

    std::cout << "=== НАСТОЯЩИЙ ГЕНЕРАТОР JWT ===" << std::endl;
    std::cout << "Секретная фраза для кодировки " + secret << std::endl;
    std::cout << "1. Введите 3 параметра " << std::endl;
        std:: cout << "Например: (Пользователь:Босс; Роль:Админ; Доступ:Полный)" << std::endl;
    std::cout << "> ";

    
    std::string raw_input;
    std::getline(std::cin, raw_input);

    
    std::string utf8_input = ConvertConsoleInputToUTF8(raw_input);

    if (utf8_input.empty()) {
        utf8_input = "Пользователь:Босс; Роль:Админ; Доступ:Полный";
        std::cout << "\n[!] Вы ничего не ввели. Используем тестовые данные:" << std::endl;
        std::cout << "[" << utf8_input << "]\n" << std::endl;
    }

    char out_buffer[1024] = { 0 };

    GenerateToken(utf8_input.c_str(), secret.c_str(), out_buffer, 1024);

    std::cout << "\n--- СГЕНЕРИРОВАННЫЙ ТОКЕН ---" << std::endl;
    std::cout << out_buffer << std::endl;

    std::cout << "\nНажмите Enter для выхода..." << std::endl;
    std::cin.get();
    return 0;
}