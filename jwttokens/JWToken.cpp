#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include <bcrypt.h>


#pragma comment(lib, "bcrypt.lib")

// Универсальная функция Base64Url кодирования
std::string base64url_encode(const unsigned char* data, size_t length) {
    std::string out;
    int val = 0, valb = -6;
    for (size_t i = 0; i < length; i++) {
        unsigned char c = data[i];
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            int index = (val >> valb) & 0x3F;
            if (index < 26) out.push_back(index + 'A');
            else if (index < 52) out.push_back(index - 26 + 'a');
            else if (index < 62) out.push_back(index - 52 + '0');
            else if (index == 62) out.push_back('-');
            else out.push_back('_');
            valb -= 6;
        }
    }
    if (valb > -6) {
        int index = ((val << 8) >> (valb + 8)) & 0x3F;
        if (index < 26) out.push_back(index + 'A');
        else if (index < 52) out.push_back(index - 26 + 'a');
        else if (index < 62) out.push_back(index - 52 + '0');
        else if (index == 62) out.push_back('-');
        else out.push_back('_');
    }
    return out;
}


std::string base64url_encode(const std::string& in) {
    return base64url_encode(reinterpret_cast<const unsigned char*>(in.data()), in.length());
}

//Создание подписи HMAC-SHA256
std::string CreateHMACSHA256(const std::string& data, const std::string& key) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD cbHashObject = 0, cbData = 0;
    std::vector<BYTE> hash(32);
    std::string result = "";
    PBYTE pbHashObject = NULL;
    LONG status = 0; 


    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (status != 0) goto cleanup; 

   
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
    if (status != 0) goto cleanup;

   
    pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
    if (pbHashObject == NULL) goto cleanup;

   
    status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, (PUCHAR)key.data(), (ULONG)key.size(), 0);
    if (status != 0) goto cleanup;

    
    status = BCryptHashData(hHash, (PUCHAR)data.data(), (ULONG)data.size(), 0);
    if (status != 0) goto cleanup;

    
    status = BCryptFinishHash(hHash, hash.data(), (ULONG)hash.size(), 0);
    if (status != 0) goto cleanup;

    
    result = base64url_encode(hash.data(), hash.size());

cleanup:
   
    if (hHash) BCryptDestroyHash(hHash);
    if (pbHashObject) HeapFree(GetProcessHeap(), 0, pbHashObject);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
        
    return result; 
}

extern "C" __declspec(dllexport) void GenerateToken(const char* parameters, const char* secret_key, char* out_buffer, int buffer_size) {
    if (!parameters || !secret_key || !out_buffer || buffer_size <= 0) return;

    // 1. Формируем заголовок и берем чистые данные от начальника (без обертки data)
    std::string header = R"({"alg":"HS256","typ":"JWT"})";
    std::string payload = std::string(parameters);

    // 2. Кодируем заголовок и данные в Base64Url (ЭТИ СТРОКИ ДОЛЖНЫ БЫТЬ ТУТ!)
    std::string b64_header = base64url_encode(header);
    std::string b64_payload = base64url_encode(payload);

    // 3. Формируем тело для подписи (Header + Payload через точку)
    std::string message_to_sign = b64_header + "." + b64_payload;

    // 4. Создаем криптографическую подпись HMAC-SHA256
    std::string signature = CreateHMACSHA256(message_to_sign, std::string(secret_key));

    // 5. Собираем финальный JWT токен
    std::string jwt_token = message_to_sign + "." + signature;

    // 6. Копируем результат в выходной буфер
    snprintf(out_buffer, buffer_size, "%s", jwt_token.c_str());
}


extern "C" __declspec(dllexport) int VerifyToken(const char* token, const char* secret_key) {
    if (!token || !secret_key) return 0;

    std::string jwt(token);

 
    size_t first_dot = jwt.find('.');
    size_t second_dot = jwt.rfind('.');

    
    if (first_dot == std::string::npos || first_dot == second_dot) return 0;


    std::string message = jwt.substr(0, second_dot);
    std::string provided_signature = jwt.substr(second_dot + 1);

    
    std::string expected_signature = CreateHMACSHA256(message, std::string(secret_key));

  
    return (provided_signature == expected_signature) ? 1 : 0;
}