# -*- coding: utf-8 -*-
import multiprocessing
import hashlib
import coincurve
from concurrent.futures import ProcessPoolExecutor, as_completed
import time
import sys

# Конфигурация
TARGET_HASH = bytes.fromhex("f6f5431d25bbf7b12e8add9af5e3475c44a0a5b8")
START_KEY = 0x60102a304e0c796a80
END_KEY = 0x80102a304e0c796a80
CHUNK_SIZE = 100000
THREADS = max(1, int(multiprocessing.cpu_count() * 1.5))  # Ядра * 1.5
REPORT_INTERVAL = 500_000  # Отчет каждые 10 млн ключей

def process_chunk(start, end, result_queue):
    """Обработка блока ключей с отправкой прогресса"""
    for key_int in range(start, end + 1):
        try:
            key_hex = f"{key_int:064x}"
            key_bytes = bytes.fromhex(key_hex)
            pub_key = coincurve.PublicKey.from_secret(key_bytes).format(compressed=True)
            h = hashlib.new('ripemd160', hashlib.sha256(pub_key).digest()).digest()
            
            if h == TARGET_HASH:
                result_queue.put(('found', key_hex))
                return
                
            if key_int % 1000 == 0:
                result_queue.put(('progress', key_int))
                
        except Exception:
            continue
    result_queue.put(('done', end))

def format_key(key_int):
    """Форматирование ключа для вывода"""
    return f"{key_int:064x}"

def find_key_parallel():
    """Параллельный поиск с улучшенным выводом информации"""
    print(f"\n⚡ Запуск поиска с {THREADS} процессами")
    print(f"🔍 Диапазон: {hex(START_KEY)}-{hex(END_KEY)}")
    print(f"🎯 Целевой хеш: {TARGET_HASH.hex()}")
    print("Подбор начался...")

    manager = multiprocessing.Manager()
    result_queue = manager.Queue()
    start_time = time.time()
    last_report_key = START_KEY
    found_key = None
    last_report_time = start_time

    # Создаем и запускаем процессы
    with ProcessPoolExecutor(max_workers=THREADS) as executor:
        chunks = [(s, min(s + CHUNK_SIZE - 1, END_KEY)) 
                 for s in range(START_KEY, END_KEY + 1, CHUNK_SIZE)]
        futures = [executor.submit(process_chunk, start, end, result_queue) 
                  for start, end in chunks]
        
        while not found_key and any(not f.done() for f in futures):
            while not result_queue.empty():
                msg_type, data = result_queue.get()
                
                if msg_type == 'progress':
                    # Выводим отчет каждые 10 млн ключей
                    if data - last_report_key >= REPORT_INTERVAL:
                        current_time = time.time()
                        time_diff = current_time - last_report_time
                        speed = REPORT_INTERVAL / max(1, time_diff)
                        
                        # Очищаем предыдущий вывод и выводим новую информацию
                        sys.stdout.write('\033[F\033[K' * 2)  # Перемещаемся на 2 строки вверх и очищаем
                        print(f"Скорость: {speed:,.0f} keys/sec")
                        print(f"Последний ключ: {format_key(data)}")
                        
                        # Обновляем счетчики
                        last_report_key = data
                        last_report_time = current_time
                        
                elif msg_type == 'found':
                    found_key = data
                    for f in futures:
                        f.cancel()
                    break

    # Вывод результатов
    elapsed = time.time() - start_time
    print(f"\nВсего времени: {elapsed:.2f} сек")
    print(f"Средняя скорость: {(END_KEY-START_KEY+1)/max(1, elapsed):,.0f} keys/sec")
    
    if found_key:
        print(f"\n🎉 КЛЮЧ НАЙДЕН!")
        print(f"🔑 Приватный ключ: {found_key}")
    else:
        print(f"\n🔍 Ключ не найден в указанном диапазоне")

if __name__ == "__main__":
    # Проверка корректности преобразований
    TEST_KEY = 0x349b84b6431a6c4ef1
    test_hex = f"{TEST_KEY:064x}"
    test_bytes = bytes.fromhex(test_hex)
    pub_key = coincurve.PublicKey.from_secret(test_bytes).format(compressed=True)
    sha256_hash = hashlib.sha256(pub_key).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    test_hash = ripemd160_hash.hex()
    
    print("🔧 Тест преобразования ключа:")
    print(f"Тестовый ключ: {test_hex}")
    print(f"Полученный хеш: {test_hash}")
    print(f"Ожидаемый хеш: {TARGET_HASH.hex()}")
    print(f"Совпадение: {test_hash == TARGET_HASH.hex()}\n")

    # Запуск параллельного поиска
    find_key_parallel()
