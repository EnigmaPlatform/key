# -*- coding: utf-8 -*-
import hashlib
import coincurve
from concurrent.futures import ProcessPoolExecutor
import time
import math

# Конфигурация
TARGET_HASH = "f6f5431d25bbf7b12e8add9af5e3475c44a0a5b8"
TEST_KEY = "0000000000000000000000000000000000000000000000000000000000000001"
START_KEY = 0x400000000000000000
END_KEY = 0x800000000000000000
THREADS = 8
REPORT_INTERVAL = 300  # 5 минут в секундах

def test_hash():
    """Тест хеширования с подробным выводом"""
    print("="*50)
    print("🔧 ТЕСТ ХЕШИРОВАНИЯ")
    print("="*50)
    
    print(f"Ключ: {TEST_KEY}")
    key_bytes = bytes.fromhex(TEST_KEY)
    
    try:
        # 1. Генерация публичного ключа
        pub_key = coincurve.PublicKey.from_secret(key_bytes).format(compressed=True)
        print(f"1. Публичный ключ: {pub_key.hex()}")
        
        # 2. SHA256
        sha256 = hashlib.sha256(pub_key).digest()
        print(f"2. SHA256: {sha256.hex()}")
        
        # 3. RIPEMD160
        ripemd160 = hashlib.new('ripemd160', sha256).digest()
        print(f"3. RIPEMD160: {ripemd160.hex()}")
        
        # 4. Сравнение
        print("\nРЕЗУЛЬТАТ:")
        print(f"Ожидаемый: {TARGET_HASH}")
        print(f"Полученный: {ripemd160.hex()}")
        print(f"Совпадение: {'✅ ВЕРНО' if ripemd160.hex() == TARGET_HASH else '❌ НЕВЕРНО'}")
        
        return ripemd160.hex() == TARGET_HASH
    except Exception as e:
        print(f"❌ Ошибка: {str(e)}")
        return False

def process_range(start, end):
    """Поиск в диапазоне ключей"""
    current = start
    last_report = time.time()
    
    while current <= end:
        try:
            key_hex = f"{current:064x}"
            key_bytes = bytes.fromhex(key_hex)
            
            pub_key = coincurve.PublicKey.from_secret(key_bytes).format(compressed=True)
            h = hashlib.new('ripemd160', hashlib.sha256(pub_key).digest()).hex()
            
            if h == TARGET_HASH:
                return key_hex
                
            if time.time() - last_report >= REPORT_INTERVAL:
                print(f"Последний проверенный: {key_hex}")
                last_report = time.time()
                
        except Exception:
            pass
            
        current += 1
        
    return None

def main():
    if not test_hash():
        print("\n❌ Тест не пройден! Проверьте настройки.")
        return
    
    print("\n" + "="*50)
    print(f"⚡ ПОИСК НА {THREADS} ЯДРАХ")
    print(f"🔍 Диапазон: {hex(START_KEY)} - {hex(END_KEY)}")
    print(f"⏱ Отчет каждые {REPORT_INTERVAL//60} мин")
    print("="*50 + "\n")
    
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
                    print(f"🎉 КЛЮЧ НАЙДЕН: {result}")
                    print("="*50)
                    for f in futures:
                        f.cancel()
                    break
        except KeyboardInterrupt:
            print("\n⏹ Поиск остановлен")
    
    print(f"\n⌛ Время работы: {time.time() - start_time:.2f} сек")

if __name__ == "__main__":
    main()
