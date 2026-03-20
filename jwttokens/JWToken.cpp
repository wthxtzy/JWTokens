#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

// --- 1. BASE64 DECODE (Для декодирования секретного ключа) ---
std::vector<BYTE> base64_decode(const std::string& in) {
    std::vector<BYTE> out;
    std::vector<int> T(256, -1);
    const char* b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (int i = 0; i < 64; i++) T[b64_chars[i]] = i;
    // Поддержка Base64Url
    T['-'] = 62; T['_'] = 63;

    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (T[c] == -1) continue;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(BYTE((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

// --- 2. BASE64URL ENCODE (Для формирования токена) ---
std::string base64url_encode(const unsigned char* data, size_t length) {
    static const char lookup[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    uint32_t buffer = 0;
    int count = 0;
    for (size_t i = 0; i < length; i++) {
        buffer = (buffer << 8) | data[i];
        count += 8;
        while (count >= 6) {
            out.push_back(lookup[(buffer >> (count - 6)) & 0x3F]);
            count -= 6;
        }
    }
    if (count > 0) out.push_back(lookup[(buffer << (6 - count)) & 0x3F]);
    return out;
}

// --- 3. HMAC-SHA256 С ПОЛНОЙ ПРОВЕРКОЙ ОШИБОК (Убираем C6031) ---
std::string CreateHMACSHA256(const std::string& data, const std::vector<BYTE>& key_bytes) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD cbHashObject = 0, cbData = 0;
    std::vector<BYTE> hash(32);
    PBYTE pbHashObject = NULL;
    std::string result = "";

    // Проверяем каждую функцию и сохраняем статус
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0) goto cleanup;

    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0) != 0) goto cleanup;

    pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
    if (!pbHashObject) goto cleanup;

    if (BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, (PUCHAR)key_bytes.data(), (ULONG)key_bytes.size(), 0) != 0) goto cleanup;

    if (BCryptHashData(hHash, (PUCHAR)data.data(), (ULONG)data.size(), 0) != 0) goto cleanup;

    if (BCryptFinishHash(hHash, hash.data(), (ULONG)hash.size(), 0) != 0) goto cleanup;

    result = base64url_encode(hash.data(), hash.size());

cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (pbHashObject) HeapFree(GetProcessHeap(), 0, pbHashObject);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}

// --- 4. ЭКСПОРТИРУЕМЫЕ ФУНКЦИИ ---

extern "C" __declspec(dllexport) void GenerateToken(const char* parameters, const char* secret_key, char* out_buffer, int buffer_size) {
    if (!parameters || !secret_key || !out_buffer || buffer_size <= 0) return;

    // Формируем заголовок (Header)
    std::string header_json = R"({"alg":"HS256","typ":"JWT"})";
    std::string h_b64 = base64url_encode((unsigned char*)header_json.c_str(), header_json.length());

    // Формируем данные (Payload)
    std::string p_b64 = base64url_encode((unsigned char*)parameters, strlen(parameters));

    // Сообщение для подписи
    std::string message = h_b64 + "." + p_b64;

    // Декодируем ключ из Base64 в байты
    std::vector<BYTE> key_bytes = base64_decode(std::string(secret_key));

    // Создаем подпись
    std::string signature = CreateHMACSHA256(message, key_bytes);

    // Итоговый токен
    std::string jwt = message + "." + signature;

    // Копируем в буфер (безопасно)
    strncpy_s(out_buffer, buffer_size, jwt.c_str(), _TRUNCATE);
}

// --- 5. ФУНКЦИИ ДЛЯ 1С (NATIVE API STUBS) ---

extern "C" __declspec(dllexport) const char* GetClassNames() {
    return "JWTLibrary";
}

extern "C" __declspec(dllexport) long GetClassObject(const char* name, void** pInterface) {
    return 0;
}

extern "C" __declspec(dllexport) long DestroyObject(void** pInterface) {
    return 0;
}