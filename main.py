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
    'SAVE_INTERVAL': 10_000_000,  # Сохранять каждый 10M ключей
    'STATUS_INTERVAL': 5  # Интервал обновления статуса (секунды)
}

def load_last_key():
    """Загружает последний сохраненный ключ"""
    if os.path.exists(CONFIG['CHECKPOINT_FILE']):
        try:
            with open(CONFIG['CHECKPOINT_FILE'], 'r') as f:
                data = json.load(f)
                return max(int(k) for k in data.keys())
        except:
            pass
    return CONFIG['START_KEY']

def save_progress(key):
    """Сохраняет прогресс"""
    progress = {str(key): time.time()}
    with open(CONFIG['CHECKPOINT_FILE'], 'a') as f:
        f.write(json.dumps(progress) + '\n')

def private_to_address(private_key_hex):
    """Оптимизированное преобразование ключа в адрес"""
    priv = bytes.fromhex(private_key_hex)
    pub = coincurve.PublicKey.from_valid_secret(priv).format(compressed=True)
    h160 = hashlib.new('ripemd160', hashlib.sha256(pub).digest()).digest()
    extended = b'\x00' + h160
    checksum = hashlib.sha256(hashlib.sha256(extended).digest()).digest()[:4]
    return base58.b58encode(extended + checksum).decode('utf-8')

def main():
    current_key = load_last_key()
    keys_checked = 0
    start_time = last_save_time = last_status_time = time.time()
    
    print("\n=== Bitcoin Puzzle Solver ===")
    print(f"Целевой адрес: {CONFIG['TARGET_ADDRESS']}")
    print(f"Диапазон: {hex(CONFIG['START_KEY'])} - {hex(CONFIG['END_KEY'])}")
    print(f"Начинаем с: {hex(current_key)}")
    print("==============================")

    try:
        while current_key <= CONFIG['END_KEY']:
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
            
            # Сохранение прогресса
            if keys_checked % CONFIG['SAVE_INTERVAL'] == 0:
                save_progress(current_key)
                last_save_time = time.time()
            
            # Вывод статуса
            current_time = time.time()
            if current_time - last_status_time >= CONFIG['STATUS_INTERVAL']:
                elapsed = current_time - start_time
                speed = int(keys_checked / elapsed)
                total_keys = CONFIG['END_KEY'] - CONFIG['START_KEY'] + 1
                processed_keys = current_key - CONFIG['START_KEY']
                percent = (processed_keys / total_keys) * 100
                
                print(f"\r[Прогресс] {percent:.2f}% | "
                      f"Ключей: {keys_checked:,} | "
                      f"Скорость: {speed:,} keys/s | "
                      f"Текущий: {hex(current_key)}", end="", flush=True)
                
                last_status_time = current_time
    
    except KeyboardInterrupt:
        print("\nОстановлено пользователем. Сохраняем прогресс...")
        save_progress(current_key)
    
    elapsed = time.time() - start_time
    print(f"\n\nПоиск завершен. Проверено ключей: {keys_checked:,}")
    print(f"Общее время: {elapsed:.1f} секунд")
    print(f"Средняя скорость: {int(keys_checked/elapsed):,} keys/s")
    print(f"Последняя позиция: {hex(current_key)}")

if __name__ == "__main__":
    main()
