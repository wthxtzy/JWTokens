#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

// --- ФУНКЦИЯ ДЕКОДИРОВАНИЯ BASE64 (чтобы ключ стал байтами) ---
std::vector<BYTE> base64_decode(const std::string& in) {
    std::vector<BYTE> out;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;
    // Поддержка Base64Url (замена - и _ на + и /)
    for (int i = 0; i < 64; i++) T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[i]] = i;

    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (T[c] == -1) continue;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

// --- ФУНКЦИЯ КОДИРОВАНИЯ BASE64URL (для результата) ---
std::string base64url_encode(const unsigned char* data, size_t length) {
    static const char lookup[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    int count = 0;
    uint32_t buffer = 0;
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

// --- СОЗДАНИЕ HMAC-SHA256 (с бинарным ключом) ---
std::string CreateHMACSHA256(const std::string& data, const std::vector<BYTE>& key_bytes) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD cbHashObject = 0, cbData = 0;
    std::vector<BYTE> hash(32);
    PBYTE pbHashObject = NULL;

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
    pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);

    // ИСПОЛЬЗУЕМ БИНАРНЫЕ БАЙТЫ КЛЮЧА
    BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, (PUCHAR)key_bytes.data(), (ULONG)key_bytes.size(), 0);
    BCryptHashData(hHash, (PUCHAR)data.data(), (ULONG)data.size(), 0);
    BCryptFinishHash(hHash, hash.data(), (ULONG)hash.size(), 0);

    BCryptDestroyHash(hHash);
    HeapFree(GetProcessHeap(), 0, pbHashObject);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return base64url_encode(hash.data(), hash.size());
}

// --- ГЛАВНАЯ ФУНКЦИЯ ---
extern "C" __declspec(dllexport) void GenerateToken(const char* parameters, const char* secret_key, char* out_buffer, int buffer_size) {
    if (!parameters || !secret_key || !out_buffer) return;

    std::string header_b64 = base64url_encode((unsigned char*)R"({"alg":"HS256","typ":"JWT"})", 27);
    std::string payload_b64 = base64url_encode((unsigned char*)parameters, strlen(parameters));
    std::string message = header_b64 + "." + payload_b64;

    // ДЕКОДИРУЕМ КЛЮЧ ИЗ BASE64 В БАЙТЫ
    std::vector<BYTE> decoded_key = base64_decode(std::string(secret_key));

    std::string signature = CreateHMACSHA256(message, decoded_key);
    std::string jwt = message + "." + signature;

    snprintf(out_buffer, buffer_size, "%s", jwt.c_str());
}