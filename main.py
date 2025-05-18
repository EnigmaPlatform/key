import hashlib
import random
import base58
import ecdsa
import time
import json
import os
from tqdm import tqdm
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor
import signal

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    END = '\033[0m'

# Конфигурация
CHECKPOINT_FILE = "checked_ranges.json"
FOUND_KEYS_FILE = "found_keys.txt"
CHUNK_SIZE = 10_000_000
MAIN_START = 0x65A4321FEDCBA98700
MAIN_END = 0x6D7A3B4F5C6D2E1F00
BATCH_SIZE = 1000
MAX_WORKERS = 4
SAVE_INTERVAL = 10

# Глобальные переменные
stop_flag = False
current_chunk = None

def load_checked_ranges():
    """Загружает проверенные диапазоны из файла"""
    if os.path.exists(CHECKPOINT_FILE):
        try:
            with open(CHECKPOINT_FILE, 'r') as f:
                return json.load(f)
        except:
            return []
    return []

def save_checked_ranges(ranges):
    """Сохраняет проверенные диапазоны в файл"""
    with open(CHECKPOINT_FILE, 'w') as f:
        json.dump(ranges, f, indent=2)

def is_key_checked(key_int, checked_ranges):
    """Проверяет, был ли ключ проверен"""
    for r in checked_ranges:
        if r['start'] <= key_int <= r['end']:
            return True
    return False

def merge_ranges(ranges):
    """Объединяет перекрывающиеся диапазоны"""
    if not ranges:
        return []
    
    sorted_ranges = sorted(ranges, key=lambda x: x['start'])
    merged = [sorted_ranges[0]]
    
    for current in sorted_ranges[1:]:
        last = merged[-1]
        if current['start'] <= last['end']:
            last['end'] = max(last['end'], current['end'])
        else:
            merged.append(current)
    
    return merged

@lru_cache(maxsize=100000)
def generate_address(private_key_hex):
    """Генерирует Bitcoin-адрес с кешированием"""
    try:
        private_key_bytes = bytes.fromhex(private_key_hex)
        sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        
        x = vk.pubkey.point.x()
        y = vk.pubkey.point.y()
        prefix = '02' if y % 2 == 0 else '03'
        public_key_compressed = bytes.fromhex(prefix + "%064x" % x)
        
        sha256 = hashlib.sha256(public_key_compressed).digest()
        ripemd160 = hashlib.new('ripemd160', sha256).digest()
        
        extended_hash = b'\x00' + ripemd160
        checksum = hashlib.sha256(hashlib.sha256(extended_hash).digest()).digest()[:4]
        return base58.b58encode(extended_hash + checksum).decode('utf-8')
    except:
        return None

def check_batch(batch, target):
    """Проверяет пакет ключей в нескольких потоках"""
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        results = list(executor.map(generate_address, batch))
        if target in results:
            return batch[results.index(target)]
    return None

def check_sequential_chunk(start_key, target_address, checked_ranges):
    """Проверяет последовательный блок ключей"""
    global stop_flag, current_chunk
    
    end_key = min(start_key + CHUNK_SIZE - 1, MAIN_END)
    current_chunk = {'start': start_key, 'end': end_key}
    
    with tqdm(total=end_key-start_key+1, 
             desc=f"Проверка {hex(start_key)}-{hex(end_key)}", 
             mininterval=2,
             bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{rate_fmt}{postfix}, {remaining}]",
             dynamic_ncols=True) as pbar:
        
        for batch_start in range(start_key, end_key+1, BATCH_SIZE):
            if stop_flag:
                break
                
            batch_end = min(batch_start + BATCH_SIZE - 1, end_key)
            batch = [format(k, '064x') for k in range(batch_start, batch_end+1)]
            
            if found_key := check_batch(batch, target_address):
                return found_key
                
            pbar.update(batch_end - batch_start + 1)
    
    if not stop_flag:
        checked_ranges.append({
            'start': start_key,
            'end': end_key,
            'checked_at': time.strftime('%Y-%m-%d %H:%M:%S')
        })
        if len(checked_ranges) % SAVE_INTERVAL == 0:
            save_checked_ranges(merge_ranges(checked_ranges))
    
    return None

def signal_handler(sig, frame):
    """Обрабатывает сигнал прерывания"""
    global stop_flag
    print(f"\n{Colors.YELLOW}Получен сигнал прерывания...{Colors.END}")
    stop_flag = True

def main(target_address="1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"):
    """Основная функция поиска"""
    global stop_flag
    
    # Настройка обработчика прерываний
    signal.signal(signal.SIGINT, signal_handler)
    
    checked_ranges = merge_ranges(load_checked_ranges())
    total_checked = sum(r['end']-r['start']+1 for r in checked_ranges)
    
    print(f"{Colors.YELLOW}Поиск ключа для адреса: {target_address}{Colors.END}")
    print(f"Уже проверено: {total_checked:,} ключей")
    print(f"Размер блока: {CHUNK_SIZE:,} ключей")
    print(f"Потоков: {MAX_WORKERS}, Пакет: {BATCH_SIZE} ключей\n")

    try:
        while not stop_flag:
            # Генерация случайного непроверенного ключа
            attempts = 0
            while not stop_flag:
                random_key = random.randint(MAIN_START, MAIN_END)
                if not is_key_checked(random_key, checked_ranges):
                    break
                attempts += 1
                if attempts > 1000:
                    print(f"{Colors.RED}Не удалось найти непроверенный ключ{Colors.END}")
                    stop_flag = True
                    break
            
            if stop_flag:
                break
                
            # Проверка случайного ключа
            random_hex = format(random_key, '064x')
            if generate_address(random_hex) == target_address:
                print(f"\n{Colors.GREEN}Ключ найден в случайной точке!{Colors.END}")
                print(f"Приватный ключ: {random_hex}")
                with open(FOUND_KEYS_FILE, "a") as f:
                    f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Private: {random_hex}\n")
                    f.write(f"Address: {target_address}\n\n")
                break
                
            # Проверка последовательного блока
            if found_key := check_sequential_chunk(random_key, target_address, checked_ranges):
                print(f"\n{Colors.GREEN}Ключ найден в последовательном блоке!{Colors.END}")
                print(f"Приватный ключ: {found_key}")
                with open(FOUND_KEYS_FILE, "a") as f:
                    f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Private: {found_key}\n")
                    f.write(f"Address: {target_address}\n\n")
                break
                
            # Проверка завершения всего диапазона
            current_coverage = sum(r['end']-r['start']+1 for r in checked_ranges)
            total_range = MAIN_END - MAIN_START + 1
            if current_coverage >= total_range:
                print(f"\n{Colors.RED}Весь диапазон проверен, ключ не найден.{Colors.END}")
                break
                
    except Exception as e:
        print(f"\n{Colors.RED}Ошибка: {e}{Colors.END}")
    finally:
        # Финализация
        if not stop_flag and current_chunk:
            checked_ranges.append(current_chunk)
        
        save_checked_ranges(merge_ranges(checked_ranges))
        total_checked = sum(r['end']-r['start']+1 for r in checked_ranges)
        
        print(f"\n{Colors.YELLOW}Итоги:{Colors.END}")
        print(f"Всего проверено: {total_checked:,} ключей")
        print(f"Сохранено диапазонов: {len(checked_ranges)}")
        
        if checked_ranges:
            last_range = max(checked_ranges, key=lambda x: x['end'])
            print(f"Последний диапазон: {hex(last_range['start'])}-{hex(last_range['end'])}")

if __name__ == "__main__":
    import sys
    main(sys.argv[1] if len(sys.argv) > 1 else "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU")
