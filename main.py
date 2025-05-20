import hashlib
import base58
import time
import json
import os
import coincurve
from multiprocessing import Pool, cpu_count, Manager
import signal

# Конфигурация
CONFIG = {
    'TARGET_ADDRESS': "19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR",
    'START_KEY': 0x349b84b6431a614ef1,
    'END_KEY': 0x349b84b6431a6c4ef1,
    'CHECKPOINT_FILE': 'progress.json',
    'FOUND_KEYS_FILE': 'found_key.txt',
    'BATCH_SIZE': 1_000_000,  # Размер блока для каждого процесса
    'PROCESSES': cpu_count(),  # Используем все ядра
    'STATUS_INTERVAL': 5  # Интервал обновления статуса
}

def init_worker():
    """Игнорируем Ctrl+C в рабочих процессах"""
    signal.signal(signal.SIGINT, signal.SIG_IGN)

def load_progress():
    """Загружаем последний сохраненный прогресс"""
    if os.path.exists(CONFIG['CHECKPOINT_FILE']):
        try:
            with open(CONFIG['CHECKPOINT_FILE'], 'r') as f:
                return json.load(f)
        except:
            pass
    return {'last_key': CONFIG['START_KEY'], 'checked_ranges': []}

def save_progress(progress):
    """Сохраняем прогресс"""
    with open(CONFIG['CHECKPOINT_FILE'], 'w') as f:
        json.dump(progress, f)

def private_to_address(private_key_hex):
    """Оптимизированное преобразование ключа в адрес"""
    priv = bytes.fromhex(private_key_hex)
    pub = coincurve.PublicKey.from_valid_secret(priv).format(compressed=True)
    h160 = hashlib.new('ripemd160', hashlib.sha256(pub).digest()).digest()
    extended = b'\x00' + h160
    checksum = hashlib.sha256(hashlib.sha256(extended).digest()).digest()[:4]
    return base58.b58encode(extended + checksum).decode('utf-8')

def process_batch(args):
    """Обрабатывает пакет ключей"""
    start_key, end_key, found_flag = args
    results = []
    
    for key in range(start_key, end_key + 1):
        if found_flag.value:
            break
            
        private_key = f"{key:064x}"
        address = private_to_address(private_key)
        
        if address == CONFIG['TARGET_ADDRESS']:
            found_flag.value = True
            return (True, key, private_key)
    
    return (False, end_key, end_key - start_key + 1)

def main():
    progress = load_progress()
    current_key = progress['last_key']
    manager = Manager()
    found_flag = manager.Value('b', False)
    
    print("\n=== Bitcoin Puzzle Solver ===")
    print(f"Целевой адрес: {CONFIG['TARGET_ADDRESS']}")
    print(f"Диапазон: {hex(CONFIG['START_KEY'])} - {hex(CONFIG['END_KEY'])}")
    print(f"Всего ключей: {(CONFIG['END_KEY']-CONFIG['START_KEY']+1):,}")
    print(f"Размер блока: {CONFIG['BATCH_SIZE']:,}")
    print(f"Процессов: {CONFIG['PROCESSES']}")
    print("==============================")

    start_time = last_status_time = time.time()
    total_keys_processed = current_key - CONFIG['START_KEY']
    
    try:
        with Pool(processes=CONFIG['PROCESSES'], initializer=init_worker) as pool:
            while current_key <= CONFIG['END_KEY'] and not found_flag.value:
                # Подготавливаем задания
                batch_end = min(current_key + CONFIG['BATCH_SIZE'] - 1, CONFIG['END_KEY'])
                batch_args = [(current_key + i * CONFIG['BATCH_SIZE'] // CONFIG['PROCESSES'],
                              min(current_key + (i + 1) * CONFIG['BATCH_SIZE'] // CONFIG['PROCESSES'] - 1, CONFIG['END_KEY']),
                              found_flag)
                             for i in range(CONFIG['PROCESSES'])]
                
                # Параллельная обработка
                results = pool.map(process_batch, batch_args)
                
                # Обработка результатов
                for result in results:
                    found, last_key, keys_processed = result
                    if found:
                        print(f"\n\n>>> КЛЮЧ НАЙДЕН! <<<")
                        print(f"Приватный ключ: {last_key[2]}")
                        print(f"Hex: {hex(last_key[1])}")
                        with open(CONFIG['FOUND_KEYS_FILE'], "w") as f:
                            f.write(f"Адрес: {CONFIG['TARGET_ADDRESS']}\n")
                            f.write(f"Ключ: {last_key[2]}\n")
                            f.write(f"Hex: {hex(last_key[1])}\n")
                        return
                    
                    total_keys_processed += keys_processed
                    current_key = max(current_key, last_key + 1)
                
                # Сохранение прогресса
                progress['last_key'] = current_key
                progress['checked_ranges'].append({
                    'start': batch_args[0][0],
                    'end': batch_args[-1][1],
                    'keys': CONFIG['BATCH_SIZE']
                })
                
                # Вывод статуса
                if time.time() - last_status_time >= CONFIG['STATUS_INTERVAL']:
                    elapsed = time.time() - start_time
                    speed = int(total_keys_processed / elapsed)
                    total_keys = CONFIG['END_KEY'] - CONFIG['START_KEY'] + 1
                    percent = (total_keys_processed / total_keys) * 100
                    
                    print(f"\r[Прогресс] {percent:.2f}% | "
                          f"Ключей: {total_keys_processed:,} | "
                          f"Скорость: {speed:,} keys/s | "
                          f"Текущий: {hex(current_key)}", end="", flush=True)
                    
                    last_status_time = time.time()
                    save_progress(progress)
    
    except KeyboardInterrupt:
        print("\nОстановлено пользователем. Сохраняем прогресс...")
    
    # Финализация
    elapsed = time.time() - start_time
    print(f"\n\nПоиск завершен. Проверено ключей: {total_keys_processed:,}")
    print(f"Общее время: {elapsed:.1f} секунд")
    print(f"Средняя скорость: {int(total_keys_processed/elapsed):,} keys/s")
    save_progress(progress)

if __name__ == "__main__":
    main()
