import os
import hashlib
import multiprocessing
import coincurve
from typing import Optional

# Конфигурация
CONFIG = {
    'TARGET_RIPEMD': bytes.fromhex("f6f5431d25bbf7b12e8add9af5e3475c44a0a5b8"),
    'START_KEY': 0x600000000000000000,
    'END_KEY': 0x7fffffffffffffffff,
    'OUTPUT_FILE': 'found_keys.txt',
    'BATCH_SIZE': 1_000_000,
    'WORKERS': multiprocessing.cpu_count(),
    'MAX_DUPLICATES': 2,  # Максимум 2 одинаковых символа подряд
    'MIN_MIXED_CHARS': 4,  # Минимум 4 цифры и 4 буквы
    'STATUS_INTERVAL': 5  # Секунды между обновлениями статуса
}

def is_valid_key(key_hex: str) -> bool:
    """Быстрая проверка ключа на соответствие условиям"""
    # Проверка на максимум 2 одинаковых символа подряд
    if ('000' in key_hex or '111' in key_hex or '222' in key_hex or '333' in key_hex or
        'aaa' in key_hex or 'bbb' in key_hex or 'ccc' in key_hex or 'ddd' in key_hex):
        return False
    
    # Проверка баланса цифр и букв
    digits = sum(c.isdigit() for c in key_hex[-16:])  # Проверяем только значимую часть
    letters = 16 - digits
    return digits >= 4 and letters >= 4

def key_to_ripemd160(key_hex: str) -> Optional[bytes]:
    """Оптимизированная конвертация ключа в RIPEMD-160"""
    try:
        priv = bytes.fromhex(key_hex)
        pub_key = coincurve.PublicKey.from_secret(priv).format(compressed=True)
        return hashlib.new('ripemd160', hashlib.sha256(pub_key).digest())
    except Exception:
        return None

def process_batch(start: int, end: int) -> Optional[str]:
    """Обработка пакета ключей с поиском совпадения"""
    for k in range(start, end + 1):
        key = f"{k:064x}"
        if not is_valid_key(key):
            continue
            
        ripemd = key_to_ripemd160(key)
        if ripemd and ripemd == CONFIG['TARGET_RIPEMD']:
            return key
    return None

def worker(input_queue, output_queue, stats):
    """Рабочий процесс для параллельной обработки"""
    while True:
        batch = input_queue.get()
        if batch is None:  # Сигнал завершения
            break
            
        start, end = batch
        found_key = process_batch(start, end)
        if found_key:
            output_queue.put(found_key)
        
        # Обновляем статистику
        with stats.get_lock():
            stats.value += end - start + 1

def save_key(key: str):
    """Сохранение найденного ключа"""
    with open(CONFIG['OUTPUT_FILE'], 'a') as f:
        f.write(f"Key: {key}\n")
        f.write(f"Address: {key_to_ripemd160(key).hex()}\n\n")

def key_searcher():
    """Основная функция поиска ключей"""
    print(f"Starting search from {hex(CONFIG['START_KEY'])} to {hex(CONFIG['END_KEY'])}")
    print(f"Workers: {CONFIG['WORKERS']} | Batch size: {CONFIG['BATCH_SIZE']:,}")
    print(f"Target RIPEMD-160: {CONFIG['TARGET_RIPEMD'].hex()}")
    
    # Очереди и разделяемая память
    input_queue = multiprocessing.Queue(maxsize=CONFIG['WORKERS'] * 2)
    output_queue = multiprocessing.Queue()
    stats = multiprocessing.Value('L', 0)
    last_status = multiprocessing.Value('d', 0.0)
    
    # Запуск рабочих процессов
    processes = []
    for _ in range(CONFIG['WORKERS']):
        p = multiprocessing.Process(
            target=worker,
            args=(input_queue, output_queue, stats),
            daemon=True
        )
        p.start()
        processes.append(p)
    
    # Заполнение очереди задач
    current = CONFIG['START_KEY']
    while current <= CONFIG['END_KEY']:
        batch_end = min(current + CONFIG['BATCH_SIZE'] - 1, CONFIG['END_KEY'])
        input_queue.put((current, batch_end))
        current = batch_end + 1
    
    # Сигнал завершения
    for _ in range(CONFIG['WORKERS']):
        input_queue.put(None)
    
    # Мониторинг прогресса
    start_time = time.time()
    while any(p.is_alive() for p in processes):
        time.sleep(0.1)
        
        # Проверка найденных ключей
        while not output_queue.empty():
            found_key = output_queue.get()
            save_key(found_key)
            print(f"\nFound matching key: {found_key}")
        
        # Вывод статуса
        with stats.get_lock(), last_status.get_lock():
            now = time.time()
            if now - last_status.value >= CONFIG['STATUS_INTERVAL']:
                elapsed = now - start_time
                keys_per_sec = stats.value / max(elapsed, 1)
                progress = (stats.value / (CONFIG['END_KEY'] - CONFIG['START_KEY'])) * 100
                
                print(
                    f"\rChecked: {stats.value:,} | "
                    f"Speed: {keys_per_sec:,.0f} keys/s | "
                    f"Progress: {progress:.4f}% | "
                    f"Elapsed: {elapsed:.1f}s",
                    end='', flush=True
                )
                last_status.value = now
    
    # Завершение
    for p in processes:
        p.join()
    
    print("\nSearch completed")

if __name__ == "__main__":
    import time
    multiprocessing.freeze_support()
    key_searcher()
