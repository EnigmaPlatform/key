import hashlib
import base58
import time
import json
import os
import coincurve
from multiprocessing import Pool, cpu_count, Manager, Value
import signal
from functools import partial

# Конфигурация
CONFIG = {
    'CHECKPOINT_FILE': 'progress.json',
    'FOUND_KEYS_FILE': 'found_key.txt',
    'BATCH_SIZE': 10_000_000,  # Увеличенный размер блока
    'PROCESSES': cpu_count(),  # Автоматическое определение ядер
    'STATUS_INTERVAL': 5  # Интервал обновления статуса
}

def init_worker():
    signal.signal(signal.SIGINT, signal.SIG_IGN)

def load_progress(target_address):
    progress_file = f'progress_{target_address}.json'
    if os.path.exists(progress_file):
        try:
            with open(progress_file, 'r') as f:
                return json.load(f)
        except:
            pass
    return None

def save_progress(target_address, current_key):
    progress_file = f'progress_{target_address}.json'
    with open(progress_file, 'w') as f:
        json.dump({'last_key': current_key, 'timestamp': time.time()}, f)

def private_to_address(private_key_hex):
    try:
        priv = bytes.fromhex(private_key_hex)
        pub = coincurve.PublicKey.from_valid_secret(priv).format(compressed=True)
        h160 = hashlib.new('ripemd160', hashlib.sha256(pub).digest()).digest()
        extended = b'\x00' + h160
        checksum = hashlib.sha256(hashlib.sha256(extended).digest()).digest()[:4]
        return base58.b58encode(extended + checksum).decode('utf-8')
    except:
        return None

def process_range(args, target_address, found_flag):
    start, end = args
    results = []
    
    for key in range(start, end + 1):
        if found_flag.value:
            return (False, 0)
            
        private_key = f"{key:064x}"
        address = private_to_address(private_key)
        
        if address == target_address:
            found_flag.value = True
            return (True, key, private_key)
    
    return (False, end - start + 1)

def generate_batches(start, end, batch_size, processes):
    total_keys = end - start + 1
    batch_size = min(batch_size, total_keys // processes)
    batches = []
    
    for i in range(0, total_keys, batch_size):
        batch_start = start + i
        batch_end = min(batch_start + batch_size - 1, end)
        batches.append((batch_start, batch_end))
    
    return batches

def main(target_address, start_key, end_key):
    # Инициализация
    progress = load_progress(target_address)
    current_key = progress['last_key'] if progress else start_key
    
    manager = Manager()
    found_flag = manager.Value('b', False)
    total_keys_processed = manager.Value('i', 0)
    start_time = last_status_time = time.time()
    
    print("\n=== Bitcoin Puzzle Solver ===")
    print(f"Целевой адрес: {target_address}")
    print(f"Диапазон: {hex(start_key)} - {hex(end_key)}")
    print(f"Всего ключей: {(end_key-start_key+1):,}")
    print(f"Процессов: {CONFIG['PROCESSES']}")
    print("==============================")

    try:
        with Pool(processes=CONFIG['PROCESSES'], initializer=init_worker) as pool:
            # Генерация батчей
            batches = generate_batches(current_key, end_key, CONFIG['BATCH_SIZE'], CONFIG['PROCESSES'])
            
            # Частичная функция для передачи дополнительных аргументов
            worker_func = partial(process_range, target_address=target_address, found_flag=found_flag)
            
            for batch in batches:
                if found_flag.value:
                    break
                    
                # Параллельная обработка
                results = pool.map(worker_func, [batch])
                
                for result in results:
                    found, *data = result
                    
                    if found:
                        key, private_key = data
                        print(f"\n\n>>> КЛЮЧ НАЙДЕН! <<<")
                        print(f"Приватный ключ: {private_key}")
                        print(f"Hex: {hex(key)}")
                        with open(CONFIG['FOUND_KEYS_FILE'], "w") as f:
                            f.write(f"Адрес: {target_address}\n")
                            f.write(f"Ключ: {private_key}\n")
                            f.write(f"Hex: {hex(key)}\n")
                        return
                    else:
                        keys_processed = data[0]
                        total_keys_processed.value += keys_processed
                        current_key = batch[1] + 1
                
                # Вывод статуса
                if time.time() - last_status_time >= CONFIG['STATUS_INTERVAL']:
                    elapsed = time.time() - start_time
                    speed = int(total_keys_processed.value / elapsed)
                    total_keys = end_key - start_key + 1
                    percent = (total_keys_processed.value / total_keys) * 100
                    
                    print(f"\r[Прогресс] {percent:.2f}% | "
                          f"Ключей: {total_keys_processed.value:,} | "
                          f"Скорость: {speed:,} keys/s | "
                          f"Текущий: {hex(current_key)}", end="", flush=True)
                    
                    last_status_time = time.time()
                    save_progress(target_address, current_key)
    
    except KeyboardInterrupt:
        print("\nОстановлено пользователем. Сохраняем прогресс...")
    
    # Финализация
    elapsed = time.time() - start_time
    print(f"\n\nПоиск завершен. Проверено ключей: {total_keys_processed.value:,}")
    print(f"Общее время: {elapsed:.1f} секунд")
    print(f"Средняя скорость: {int(total_keys_processed.value/elapsed):,} keys/s")
    save_progress(target_address, current_key)

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 4:
        print("Использование: python script.py <адрес> <начальный_ключ> <конечный_ключ>")
        print("Пример: python script.py 1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU 0x1A12F1DA9D7000000 0x1A12F1DA9DFFFFFFF")
        sys.exit(1)
    
    target_address = sys.argv[1]
    start_key = int(sys.argv[2], 16)
    end_key = int(sys.argv[3], 16)
    
    main(target_address, start_key, end_key)
