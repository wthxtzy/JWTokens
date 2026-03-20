#include <iostream>
#include <string>
#include <windows.h> 
#include <algorithm>
#include <fstream>  // Для работы с файлами

extern "C" void GenerateToken(const char* parameters, const char* secret_key, char* out_buffer, int buffer_size);

// Вспомогательная функция для очистки текста (Trim)
std::string Trim(std::string s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) { return !std::isspace(ch); }));
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base(), s.end());
    return s;
}

// Функция для перевода из кодировки консоли в UTF-8
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

// Удаление лишних пробелов из JSON
std::string Minify(std::string str) {
    std::string result;
    for (char c : str) { if (c != ' ' && c != '\n' && c != '\r' && c != '\t') result += c; }
    return result;
}

int main() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    const std::string filename = "secret.txt";
    // Ключ по умолчанию (тот самый, от Максима)
    std::string current_secret = "oMtcctQzqo3jpFIL9B8qVwTgGBmfzFb2";

    // 1. ПЫТАЕМСЯ ПРОЧИТАТЬ СОХРАНЕННЫЙ КЛЮЧ ИЗ ФАЙЛА
    std::ifstream infile(filename);
    if (infile.is_open()) {
        std::getline(infile, current_secret);
        current_secret = Trim(current_secret);
        infile.close();
    }

    std::cout << "===JWT GENERATOR ===" << std::endl;
    std::cout << "[ТЕКУЩИЙ КЛЮЧ]: " << current_secret << std::endl;

    // 2. СПРАШИВАЕМ, НУЖНО ЛИ ЕГО ИЗМЕНИТЬ
    std::cout << "\nВведите НОВЫЙ секретный ключ или нажмите ENTER, чтобы оставить текущий:" << std::endl;
    std::cout << "> ";
    std::string new_secret;
    std::getline(std::cin, new_secret);
    new_secret = Trim(new_secret);

    if (!new_secret.empty()) {
        current_secret = new_secret;
        // СОХРАНЯЕМ НОВЫЙ КЛЮЧ В ФАЙЛ
        std::ofstream outfile(filename);
        if (outfile.is_open()) {
            outfile << current_secret;
            outfile.close();
            std::cout << "[✓] Новый ключ сохранен в " << filename << std::endl;
        }
    }
    else {
        std::cout << "[i] Используем текущий ключ." << std::endl;
    }

    // 3. ВВОД ДАННЫХ (PAYLOAD)
    std::cout << "\nВСТАВЬТЕ JSON (Payload) И НАЖМИТЕ ENTER ДВАЖДЫ:" << std::endl;
    std::cout << "------------------------------------------------------------" << std::endl;

    std::string full_input = "";
    std::string line;
    while (std::getline(std::cin, line) && !line.empty()) {
        full_input += line;
    }

    std::string clean_payload = Minify(ConvertConsoleInputToUTF8(full_input));

    if (clean_payload.empty()) {
        std::cout << "[!] Данные пусты!" << std::endl;
        return 0;
    }

    // 4. ГЕНЕРАЦИЯ
    char out_buffer[1024] = { 0 };
    GenerateToken(clean_payload.c_str(), current_secret.c_str(), out_buffer, 1024);

    std::cout << "\n--- ВАШ JWT ТОКЕН ---" << std::endl;
    std::cout << out_buffer << std::endl;

    std::cout << "\nНажмите Enter для выхода..." << std::endl;
    std::cin.get();
    return 0;
}