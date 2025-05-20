import hashlib
import base58
import time
import json
import os
import coincurve

# Конфигурация
CONFIG = {
    'TARGET_ADDRESS': "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU",
    'START_KEY': 0x1A12F1DA9D7000000,
    'END_KEY': 0x1A12F1DA9DFFFFFFF,
    'CHECKPOINT_FILE': 'progress.json',
    'FOUND_KEYS_FILE': 'found_key.txt',
    'BATCH_SIZE': 10_000_000,  # Размер блока для сохранения прогресса
    'STATUS_INTERVAL': 5  # Интервал обновления статуса (секунды)
}

def load_progress():
    """Загружает прогресс из файла"""
    if os.path.exists(CONFIG['CHECKPOINT_FILE']):
        try:
            with open(CONFIG['CHECKPOINT_FILE'], 'r') as f:
                return json.load(f)
        except:
            pass
    return {'last_key': CONFIG['START_KEY'], 'keys_checked': 0, 'checked_ranges': []}

def save_progress(progress):
    """Сохраняет текущий прогресс"""
    with open(CONFIG['CHECKPOINT_FILE'], 'w') as f:
        json.dump(progress, f)

def private_to_address(private_key_hex):
    """Конвертирует приватный ключ в адрес"""
    priv = bytes.fromhex(private_key_hex)
    pub = coincurve.PublicKey.from_valid_secret(priv).format(compressed=True)
    h160 = hashlib.new('ripemd160', hashlib.sha256(pub).digest()).digest()
    extended = b'\x00' + h160
    checksum = hashlib.sha256(hashlib.sha256(extended).digest()).digest()[:4]
    return base58.b58encode(extended + checksum).decode('utf-8')

def format_speed(speed):
    """Форматирует скорость перебора"""
    if speed >= 1_000_000:
        return f"{speed/1_000_000:.1f}M keys/s"
    return f"{speed/1_000:.1f}K keys/s"

def main():
    # Загрузка прогресса
    progress = load_progress()
    current_key = progress['last_key']
    keys_checked = progress['keys_checked']
    checked_ranges = progress['checked_ranges']
    
    # Инициализация
    start_time = time.time()
    last_status_time = time.time()
    last_batch_saved = current_key // CONFIG['BATCH_SIZE']
    
    print("\n=== Bitcoin Puzzle Solver ===")
    print(f"Целевой адрес: {CONFIG['TARGET_ADDRESS']}")
    print(f"Диапазон: {hex(CONFIG['START_KEY'])} - {hex(CONFIG['END_KEY'])}")
    print(f"Всего ключей: {(CONFIG['END_KEY']-CONFIG['START_KEY']+1):,}")
    print(f"Продолжаем с: {hex(current_key)}")
    print("==============================")

    try:
        while current_key <= CONFIG['END_KEY']:
            # Проверка ключа
            private_key = f"{current_key:064x}"
            address = private_to_address(private_key)
            
            if address == CONFIG['TARGET_ADDRESS']:
                print(f"\n\n>>> КЛЮЧ НАЙДЕН! <<<")
                print(f"Приватный ключ: {private_key}")
                print(f"Hex: {hex(current_key)}")
                with open(CONFIG['FOUND_KEYS_FILE'], "w") as f:
                    f.write(f"Адрес: {CONFIG['TARGET_ADDRESS']}\n")
                    f.write(f"Ключ: {private_key}\n")
                    f.write(f"Hex: {hex(current_key)}\n")
                return
            
            keys_checked += 1
            current_key += 1
            
            # Сохранение прогресса по блокам
            current_batch = current_key // CONFIG['BATCH_SIZE']
            if current_batch > last_batch_saved:
                batch_start = current_batch * CONFIG['BATCH_SIZE']
                batch_end = (current_batch + 1) * CONFIG['BATCH_SIZE'] - 1
                checked_ranges.append({
                    'start': batch_start,
                    'end': min(batch_end, CONFIG['END_KEY']),
                    'keys': CONFIG['BATCH_SIZE']
                })
                last_batch_saved = current_batch
                progress = {
                    'last_key': current_key,
                    'keys_checked': keys_checked,
                    'checked_ranges': checked_ranges
                }
                save_progress(progress)
            
            # Вывод статуса
            current_time = time.time()
            if current_time - last_status_time >= CONFIG['STATUS_INTERVAL']:
                elapsed = current_time - start_time
                speed = int(keys_checked / elapsed) if elapsed > 0 else 0
                total_keys = CONFIG['END_KEY'] - CONFIG['START_KEY'] + 1
                percent = (keys_checked / total_keys) * 100
                
                print(f"\r[Прогресс] {percent:.2f}% | "
                      f"Ключей: {keys_checked:,} | "
                      f"Скорость: {format_speed(speed)} | "
                      f"Текущий: {hex(current_key)}", end="", flush=True)
                
                last_status_time = current_time
    
    except KeyboardInterrupt:
        print("\nОстановлено пользователем. Сохраняем прогресс...")
    
    # Финализация
    progress = {
        'last_key': current_key,
        'keys_checked': keys_checked,
        'checked_ranges': checked_ranges
    }
    save_progress(progress)
    
    elapsed = time.time() - start_time
    print(f"\n\nПоиск завершен. Проверено ключей: {keys_checked:,}")
    print(f"Общее время: {elapsed:.1f} секунд")
    print(f"Средняя скорость: {format_speed(int(keys_checked/elapsed))}")
    print(f"Последняя позиция: {hex(current_key)}")

if __name__ == "__main__":
    main()
