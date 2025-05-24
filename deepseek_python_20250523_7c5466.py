# -*- coding: utf-8 -*-
import multiprocessing
import hashlib
import coincurve
from tqdm import tqdm
from concurrent.futures import ProcessPoolExecutor, as_completed
import time
import sys

# Конфигурация
TARGET_HASH = bytes.fromhex("f6f5431d25bbf7b12e8add9af5e3475c44a0a5b8")
START_KEY = 0x400000000000000000
END_KEY = 0x800000000000000000
CHUNK_SIZE = 1000000
THREADS = multiprocessing.cpu_count()
REPORT_INTERVAL = 1_000_000  # Отчет каждые 1 млн ключей

def process_chunk(start, end, result_queue):
    """Обработка блока ключей с отправкой прогресса"""
    current = start
    while current <= end:
        try:
            key_hex = f"{current:064x}"
            key_bytes = bytes.fromhex(key_hex)
            pub_key = coincurve.PublicKey.from_secret(key_bytes).format(compressed=True)
            h = hashlib.new('ripemd160', hashlib.sha256(pub_key).digest()).digest()
            
            if h == TARGET_HASH:
                result_queue.put(('found', key_hex))
                return
                
            if current % 1000 == 0:
                result_queue.put(('progress', current))
                
            current += 1
            
        except Exception:
            current += 1
            continue
            
    result_queue.put(('done', end))

def format_key(key_int):
    """Форматирование ключа для вывода"""
    return f"{key_int:064x}"

def find_key_parallel():
    """Параллельный поиск без предварительного создания диапазонов"""
    print(f"\n⚡ Запуск поиска с {THREADS} ядрами")
    print(f"🔍 Диапазон: {hex(START_KEY)}-{hex(END_KEY)}")
    print(f"🎯 Целевой хеш: {TARGET_HASH.hex()}")
    total_keys = END_KEY - START_KEY + 1
    print(f"Всего ключей: {total_keys:,}\n")

    manager = multiprocessing.Manager()
    result_queue = manager.Queue()
    start_time = time.time()
    last_report_key = START_KEY
    found_key = None
    last_progress_time = start_time
    last_progress_count = 0

    with ProcessPoolExecutor(max_workers=THREADS) as executor:
        # Распределяем диапазоны между процессами без создания полного списка
        chunk_starts = range(START_KEY, END_KEY + 1, (END_KEY - START_KEY) // THREADS + 1)
        futures = []
        
        for i in range(len(chunk_starts)):
            start = chunk_starts[i]
            end = chunk_starts[i + 1] - 1 if i < len(chunk_starts) - 1 else END_KEY
            futures.append(executor.submit(process_chunk, start, end, result_queue))

        # Прогресс-бар
        progress_bar = tqdm(total=total_keys, desc="Прогресс", unit="key", 
                          bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]")
        
        while not found_key and any(not f.done() for f in futures):
            while not result_queue.empty():
                msg_type, data = result_queue.get()
                
                if msg_type == 'progress':
                    progress_bar.update(data - progress_bar.n)
                    
                    # Рассчитываем текущую скорость
                    current_time = time.time()
                    time_diff = current_time - last_progress_time
                    keys_diff = data - last_progress_count
                    
                    if time_diff > 0:
                        current_speed = keys_diff / time_diff
                    else:
                        current_speed = 0
                    
                    if data - last_report_key >= REPORT_INTERVAL:
                        sys.stdout.write('\033[F\033[K')
                        print(f"Последний ключ: {format_key(data)} | Скорость: {current_speed:,.0f} keys/s")
                        last_report_key = data
                        last_progress_time = current_time
                        last_progress_count = data
                        
                elif msg_type == 'found':
                    found_key = data
                    for f in futures:
                        f.cancel()
                    break

    progress_bar.close()
    
    # Вывод результатов
    elapsed = time.time() - start_time
    print(f"\n{'='*50}")
    print(f"Всего времени: {elapsed:.2f} сек")
    print(f"Средняя скорость: {total_keys/max(1, elapsed):,.0f} keys/sec")
    
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
