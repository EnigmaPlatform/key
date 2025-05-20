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
    'HEX_PATTERN': '1a12f1d',
    'BANNED_SUFFIXES': ['aaaa', 'ffff'],
    'BIT_TRANSITIONS_RANGE': (7, 9),
    'CHECKPOINT_FILE': 'progress.json',
    'STATUS_INTERVAL': 5  # секунды между обновлениями статуса
}

def load_progress():
    """Загружает прогресс из файла"""
    if os.path.exists(CONFIG['CHECKPOINT_FILE']):
        try:
            with open(CONFIG['CHECKPOINT_FILE'], 'r') as f:
                return json.load(f)
        except:
            return {'last_key': CONFIG['START_KEY'], 'keys_checked': 0, 'valid_keys': 0}
    return {'last_key': CONFIG['START_KEY'], 'keys_checked': 0, 'valid_keys': 0}

def save_progress(current_key, keys_checked, valid_keys):
    """Сохраняет текущий прогресс"""
    progress = {
        'last_key': current_key,
        'keys_checked': keys_checked,
        'valid_keys': valid_keys,
        'timestamp': time.time()
    }
    with open(CONFIG['CHECKPOINT_FILE'], 'w') as f:
        json.dump(progress, f)

def count_bit_transitions(key):
    """Оптимизированный подсчет битовых переходов"""
    xor = key ^ (key >> 1)
    return bin(xor).count('1')

def is_valid_key(key):
    """Проверка ключа по всем критериям"""
    hex_key = f"{key:016x}"
    
    if CONFIG['HEX_PATTERN'] not in hex_key:
        return False
        
    if any(hex_key.endswith(s) for s in CONFIG['BANNED_SUFFIXES']):
        return False
        
    transitions = count_bit_transitions(key)
    if not CONFIG['BIT_TRANSITIONS_RANGE'][0] <= transitions <= CONFIG['BIT_TRANSITIONS_RANGE'][1]:
        return False
        
    return True

def private_to_address(private_key_hex):
    """Конвертация приватного ключа в адрес"""
    priv = bytes.fromhex(private_key_hex)
    pub = coincurve.PublicKey.from_valid_secret(priv).format(compressed=True)
    h160 = hashlib.new('ripemd160', hashlib.sha256(pub).digest()).digest()
    extended = b'\x00' + h160
    checksum = hashlib.sha256(hashlib.sha256(extended).digest()).digest()[:4]
    return base58.b58encode(extended + checksum).decode('utf-8')

def format_speed(speed):
    """Форматирование скорости"""
    if speed >= 1_000_000:
        return f"{speed/1_000_000:.1f}M keys/s"
    elif speed >= 1_000:
        return f"{speed/1_000:.1f}K keys/s"
    return f"{speed:,} keys/s"

def main():
    # Загрузка прогресса
    progress = load_progress()
    current_key = progress['last_key']
    total_keys_checked = progress['keys_checked']
    valid_keys = progress['valid_keys']
    
    # Статистика
    start_time = time.time()
    last_save_time = time.time()
    last_status_time = time.time()
    
    print("\n=== Bitcoin Puzzle Solver ===")
    print(f"Целевой адрес: {CONFIG['TARGET_ADDRESS']}")
    print(f"Диапазон: {hex(CONFIG['START_KEY'])} - {hex(CONFIG['END_KEY'])}")
    print(f"Всего ключей: {(CONFIG['END_KEY']-CONFIG['START_KEY']+1):,}")
    print(f"Продолжаем с: {hex(current_key)}")
    print("==============================")
    
    try:
        while current_key <= CONFIG['END_KEY']:
            # Проверка ключа
            if is_valid_key(current_key):
                valid_keys += 1
                private_key = f"{current_key:064x}"
                address = private_to_address(private_key)
                
                if address == CONFIG['TARGET_ADDRESS']:
                    print(f"\n\n>>> КЛЮЧ НАЙДЕН! <<<")
                    print(f"Приватный ключ: {private_key}")
                    print(f"Hex: {hex(current_key)}")
                    with open("found_key.txt", "w") as f:
                        f.write(f"Адрес: {CONFIG['TARGET_ADDRESS']}\n")
                        f.write(f"Ключ: {private_key}\n")
                        f.write(f"Hex: {hex(current_key)}\n")
                    return
            
            total_keys_checked += 1
            current_key += 1
            
            # Обновление статуса
            current_time = time.time()
            if current_time - last_status_time >= CONFIG['STATUS_INTERVAL']:
                elapsed = current_time - start_time
                speed = int(total_keys_checked / elapsed) if elapsed > 0 else 0
                total_keys = CONFIG['END_KEY'] - CONFIG['START_KEY'] + 1
                percent = (total_keys_checked / total_keys) * 100
                
                print(f"\r[Прогресс] {percent:.2f}% | "
                      f"Ключей: {total_keys_checked:,} | "
                      f"Валидных: {valid_keys:,} | "
                      f"Скорость: {format_speed(speed)} | "
                      f"Текущий: {hex(current_key)}", end="", flush=True)
                
                last_status_time = current_time
            
            # Автосохранение каждые 30 секунд
            if current_time - last_save_time >= 30:
                save_progress(current_key, total_keys_checked, valid_keys)
                last_save_time = current_time
    
    except KeyboardInterrupt:
        print("\nОстановлено пользователем. Сохраняем прогресс...")
    
    # Финализация
    save_progress(current_key, total_keys_checked, valid_keys)
    elapsed = time.time() - start_time
    print(f"\n\nПоиск завершен. Проверено ключей: {total_keys_checked:,}")
    print(f"Валидных ключей: {valid_keys:,}")
    print(f"Общее время: {elapsed:.1f} секунд")
    print(f"Средняя скорость: {format_speed(int(total_keys_checked/elapsed))}")
    print(f"Последняя позиция: {hex(current_key)}")

if __name__ == "__main__":
    main()
