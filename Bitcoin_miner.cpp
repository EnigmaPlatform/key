#include <iostream>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

// Конфигурация
const std::string TARGET_HASH = "f6f5431d25bbf7b12e8add9af5e3475c44a0a5b8";
const uint64_t START_RANGE = 0x400000000000000000;
const uint64_t END_RANGE = 0x7fffffffffffffffff;
const int NUM_THREADS = std::thread::hardware_concurrency();
const uint64_t CHUNK_SIZE = 100000000;
const int REPORT_INTERVAL_MS = 1000;

// Глобальные переменные
std::atomic<uint64_t> total_checked(0);
std::atomic<bool> found(false);
std::mutex cout_mutex;

// Функция для преобразования байт в hex-строку
std::string bytes_to_hex(const unsigned char* data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << (int)data[i];
    }
    return ss.str();
}

// Проверка валидности ключа
bool is_valid_key(const std::string& key_hex) {
    if (key_hex.length() != 64) return false;
    
    // Проверка префикса (46 нулей)
    for (int i = 0; i < 46; ++i) {
        if (key_hex[i] != '0') return false;
    }
    
    // Проверка первого значащего символа
    char first_char = key_hex[46];
    if (first_char != '4' && first_char != '5' && first_char != '6' && first_char != '7') {
        return false;
    }
    
    // Проверка на повторяющиеся последовательности
    const std::string& last_17 = key_hex.substr(47);
    for (size_t i = 0; i < last_17.length() - 4; ++i) {
        if (last_17[i] == last_17[i+1] && last_17[i] == last_17[i+2] && 
            last_17[i] == last_17[i+3] && last_17[i] == last_17[i+4]) {
            return false;
        }
    }
    
    return true;
}

// Генерация публичного ключа и хеша
void process_key(const std::string& key_hex) {
    // Конвертируем hex в байты
    std::vector<unsigned char> private_key;
    for (size_t i = 0; i < key_hex.length(); i += 2) {
        std::string byteString = key_hex.substr(i, 2);
        private_key.push_back(static_cast<unsigned char>(strtol(byteString.c_str(), nullptr, 16)));
    }

    // Создаем EC_KEY
    EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
    BIGNUM* bn = BN_new();
    BN_hex2bn(&bn, key_hex.c_str());
    EC_KEY_set_private_key(eckey, bn);

    // Получаем публичный ключ в сжатом формате
    const EC_POINT* pub_key = EC_KEY_get0_public_key(eckey);
    point_conversion_form_t form = POINT_CONVERSION_COMPRESSED;
    size_t pub_len = EC_POINT_point2oct(EC_KEY_get0_group(eckey), pub_key, 
                                       form, nullptr, 0, nullptr);
    std::vector<unsigned char> pub_key_bytes(pub_len);
    EC_POINT_point2oct(EC_KEY_get0_group(eckey), pub_key, 
                      form, pub_key_bytes.data(), pub_len, nullptr);

    // Вычисляем SHA-256
    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
    SHA256(pub_key_bytes.data(), pub_len, sha256_hash);

    // Вычисляем RIPEMD-160
    unsigned char ripemd160_hash[RIPEMD160_DIGEST_LENGTH];
    RIPEMD160(sha256_hash, SHA256_DIGEST_LENGTH, ripemd160_hash);

    // Сравниваем с целевым хешем
    std::string result_hash = bytes_to_hex(ripemd160_hash, RIPEMD160_DIGEST_LENGTH);
    if (result_hash == TARGET_HASH) {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "\nFOUND KEY: " << key_hex << std::endl;
        found = true;
    }

    // Освобождаем ресурсы
    BN_free(bn);
    EC_KEY_free(eckey);
}

// Функция для работы потока
void worker(uint64_t start, uint64_t end) {
    uint64_t local_checked = 0;
    uint64_t current = start;
    
    while (current <= end && !found) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0') << std::setw(64) << current;
        std::string key_hex = ss.str();
        
        if (is_valid_key(key_hex)) {
            process_key(key_hex);
        }
        
        current++;
        local_checked++;
        
        if (local_checked % 10000 == 0) {
            total_checked += 10000;
            local_checked = 0;
        }
    }
}

// Функция для отображения прогресса
void progress_monitor() {
    auto start_time = std::chrono::steady_clock::now();
    uint64_t last_count = 0;
    
    while (!found) {
        std::this_thread::sleep_for(std::chrono::milliseconds(REPORT_INTERVAL_MS));
        
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
        if (elapsed == 0) elapsed = 1;
        
        uint64_t current_count = total_checked;
        uint64_t checked_since_last = current_count - last_count;
        double speed = checked_since_last / (REPORT_INTERVAL_MS / 1000.0);
        
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "\rChecked: " << current_count 
                  << " | Speed: " << static_cast<int>(speed) << " keys/sec"
                  << " | Threads: " << NUM_THREADS
                  << std::flush;
        
        last_count = current_count;
    }
}

int main() {
    std::cout << "=== BITCOIN PRIVATE KEY MINER ===" << std::endl;
    std::cout << "Target hash: " << TARGET_HASH << std::endl;
    std::cout << "Using " << NUM_THREADS << " threads" << std::endl;
    
    // Запуск потоков
    std::vector<std::thread> threads;
    uint64_t range_per_thread = (END_RANGE - START_RANGE) / NUM_THREADS;
    
    // Запуск монитора прогресса
    std::thread monitor(progress_monitor);
    
    // Запуск рабочих потоков
    for (int i = 0; i < NUM_THREADS; ++i) {
        uint64_t start = START_RANGE + i * range_per_thread;
        uint64_t end = (i == NUM_THREADS - 1) ? END_RANGE : start + range_per_thread - 1;
        threads.emplace_back(worker, start, end);
    }
    
    // Ожидание завершения потоков
    for (auto& t : threads) {
        t.join();
    }
    
    monitor.join();
    
    if (!found) {
        std::cout << "\nSearch completed. Key not found." << std::endl;
    }
    
    return 0;
}
