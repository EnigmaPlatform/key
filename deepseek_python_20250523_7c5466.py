# -*- coding: utf-8 -*-
import hashlib
import coincurve
from concurrent.futures import ProcessPoolExecutor
import time
import math

# Конфигурация
TARGET_HASH = "751e76e8199196d454941c45d1b3a323f1433bd6"
TEST_KEY = "0000000000000000000000000000000000000000000000000000000000000001"
START_KEY = 0x400000000000000000
END_KEY = 0x800000000000000000
THREADS = 8
REPORT_INTERVAL = 300  # 5 минут в секундах
MIN_ENTROPY = 2.0      # Минимальная энтропия (бит/байт)
MIN_UNIQUE_BYTES = 32  # Минимум 32 уникальных байта из 64

def calculate_entropy(key_bytes):
    """Вычисляет энтропию ключа"""
    counts = {}
    for byte in key_bytes:
        counts[byte] = counts.get(byte, 0) + 1
    
    entropy = 0.0
    total = len(key_bytes)
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    
    return entropy

def is_valid_key(key_bytes):
    """Проверяет ключ на соответствие требованиям"""
    unique_bytes = len(set(key_bytes))
    entropy = calculate_entropy(key_bytes)
    return unique_bytes >= MIN_UNIQUE_BYTES and entropy >= MIN_ENTROPY

def test_hash():
    """Детальный тест хеширования"""
    print("="*50)
    print("🔧 ТЕСТ ХЕШИРОВАНИЯ")
    print("="*50)
    
    key_bytes = bytes.fromhex(TEST_KEY)
    print(f"Тестовый ключ: {TEST_KEY}")
    print(f"Уникальных байтов: {len(set(key_bytes))}/64")
    print(f"Энтропия: {calculate_entropy(key_bytes):.2f} бит/байт")
    print(f"Валидность: {'✅ Да' if is_valid_key(key_bytes) else '❌ Нет (пропустит при поиске)'}")
    
    try:
        print("\n1. Генерация публичного ключа...")
        pub_key = coincurve.PublicKey.from_secret(key_bytes).format(compressed=True)
        print(f"Публичный ключ: {pub_key.hex()}")
        
        print("\n2. Вычисление SHA256...")
        sha256 = hashlib.sha256(pub_key).digest()
        print(f"SHA256: {sha256.hex()}")
        
        print("\n3. Вычисление RIPEMD160...")
        ripemd160 = hashlib.new('ripemd160', sha256).digest()
        print(f"RIPEMD160: {ripemd160.hex()}")
        
        print("\n4. Сравнение с целевым хешем:")
        print(f"Ожидаемый: {TARGET_HASH}")
        print(f"Полученный: {ripemd160.hex()}")
        print(f"Совпадение: {'✅ Верно' if ripemd160.hex() == TARGET_HASH else '❌ Неверно'}")
        
        return ripemd160.hex() == TARGET_HASH
    except Exception as e:
        print(f"\n❌ Ошибка: {str(e)}")
        return False

def process_range(start, end):
    """Обрабатывает диапазон ключей с фильтрацией"""
    current = start
    last_report = time.time()
    
    while current <= end:
        try:
            key_hex = f"{current:064x}"
            key_bytes = bytes.fromhex(key_hex)
            
            if not is_valid_key(key_bytes):
                current += 1
                continue
                
            pub_key = coincurve.PublicKey.from_secret(key_bytes).format(compressed=True)
            ripemd160 = hashlib.new('ripemd160', hashlib.sha256(pub_key).digest()).hex()
            
            if ripemd160 == TARGET_HASH:
                return f"Найден ключ: {key_hex}"
                
            if time.time() - last_report >= REPORT_INTERVAL:
                print(f"Последний проверенный ключ: {key_hex}")
                last_report = time.time()
                
        except Exception:
            pass
            
        current += 1
        
    return None

def main():
    if not test_hash():
        print("\n❌ Тест не пройден, проверьте настройки!")
        return
    
    print(f"\n⚡ Начало поиска с {THREADS} потоками")
    print(f"🔍 Диапазон: {hex(START_KEY)} - {hex(END_KEY)}")
    print(f"⏱ Отчет каждые {REPORT_INTERVAL//60} минут\n")
    
    start_time = time.time()
    
    with ProcessPoolExecutor(max_workers=THREADS) as executor:
        chunk_size = (END_KEY - START_KEY) // THREADS
        futures = []
        
        for i in range(THREADS):
            start = START_KEY + i * chunk_size
            end = start + chunk_size - 1 if i < THREADS - 1 else END_KEY
            futures.append(executor.submit(process_range, start, end))
        
        try:
            for future in futures:
                result = future.result()
                if result:
                    print("\n" + "="*50)
                    print(result)
                    print("="*50)
                    for f in futures:
                        f.cancel()
                    break
        except KeyboardInterrupt:
            print("\n⏹ Поиск прерван пользователем")
            for f in futures:
                f.cancel()
    
    print(f"\nПоиск завершен за {time.time() - start_time:.2f} секунд")

if __name__ == "__main__":
    main()
