import hashlib
import base58
import time
import json
import os
from concurrent.futures import ProcessPoolExecutor, as_completed
import signal
import multiprocessing
import coincurve
from typing import List, Dict, Optional, Tuple
from functools import lru_cache

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    END = '\033[0m'

CONFIG = {
    'CHECKPOINT_FILE': "checked_ranges.json",
    'FOUND_KEYS_FILE': "found_keys.txt",
    'BATCH_SIZE': 100_000,
    'MAX_WORKERS': multiprocessing.cpu_count(),
    'STATUS_INTERVAL': 5,
    'PRIORITY_START': 0x1A12F1DA9D7015A3F,  # Зона A (высокий приоритет)
    'PRIORITY_END': 0x1A12F1DA9D701FFFF,
    'MAIN_START': 0x1A12F1DA9D7000000,
    'MAIN_END': 0x1A32F2ECBE8000000,
    'TARGET_ADDRESS': "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU",
    'HEX_PATTERNS': ['1a12f1d', '15a3f'],  # Ключевые паттерны
    'BANNED_PATTERNS': ['aaaa', 'ffff']    # Запрещенные комбинации
}

def init_worker():
    signal.signal(signal.SIGINT, signal.SIG_IGN)

def load_checked_ranges() -> List[Dict]:
    if os.path.exists(CONFIG['CHECKPOINT_FILE']):
        try:
            with open(CONFIG['CHECKPOINT_FILE'], 'r') as f:
                return json.load(f)
        except:
            return []
    return []

def save_checked_ranges(ranges: List[Dict]):
    try:
        with open(CONFIG['CHECKPOINT_FILE'], 'w') as f:
            json.dump(ranges, f, indent=2)
    except Exception as e:
        print(f"{Colors.RED}Checkpoint save error: {e}{Colors.END}")

def is_range_checked(start: int, end: int, ranges: List[Dict]) -> bool:
    return any(r['start'] <= start and r['end'] >= end for r in ranges)

def is_valid_key(key: int) -> bool:
    """Проверка ключа по всем выявленным закономерностям"""
    hex_key = hex(key)[2:]
    return (
        any(p in hex_key for p in CONFIG['HEX_PATTERNS']) and
        not any(b in hex_key for b in CONFIG['BANNED_PATTERNS']) and
        7 <= bin(key).count('01') <= 9
    )

@lru_cache(maxsize=100000)
def private_to_address(private_key_hex: str) -> Optional[str]:
    try:
        priv = bytes.fromhex(private_key_hex)
        pub = coincurve.PublicKey.from_valid_secret(priv).format(compressed=True)
        h160 = hashlib.new('ripemd160', hashlib.sha256(pub).digest()).digest()
        extended = b'\x00' + h160
        checksum = hashlib.sha256(hashlib.sha256(extended).digest()).digest()[:4]
        return base58.b58encode(extended + checksum).decode('utf-8')
    except:
        return None

def process_range(start: int, end: int, target: str) -> Optional[Tuple[int, str]]:
    """Обрабатывает диапазон с проверкой валидности ключа"""
    for k in range(start, end + 1):
        if not is_valid_key(k):
            continue
            
        private_key = f"{k:064x}"
        if private_to_address(private_key) == target:
            return (k, private_key)
    return None

def generate_search_ranges(checked_ranges: List[Dict]) -> List[Tuple[int, int]]:
    """Генерирует приоритетные диапазоны поиска"""
    ranges = []
    
    # 1. Проверяем зону высокого приоритета
    if not is_range_checked(CONFIG['PRIORITY_START'], CONFIG['PRIORITY_END'], checked_ranges):
        ranges.append((CONFIG['PRIORITY_START'], CONFIG['PRIORITY_END']))
    
    # 2. Делим основной диапазон на части
    total_range = CONFIG['MAIN_END'] - CONFIG['MAIN_START'] + 1
    chunk_size = total_range // (CONFIG['MAX_WORKERS'] * 4)  # Меньшие чанки для балансировки
    
    for i in range(0, total_range, chunk_size):
        start = CONFIG['MAIN_START'] + i
        end = min(start + chunk_size - 1, CONFIG['MAIN_END'])
        
        if not is_range_checked(start, end, checked_ranges):
            ranges.append((start, end))
    
    return ranges

def display_status(start_time: float, checked: int, total: int, last_range: Tuple[int, int]):
    elapsed = time.time() - start_time
    percent = (checked / total) * 100
    speed = int(checked / elapsed) if elapsed > 0 else 0
    
    print(f"\n{Colors.YELLOW}=== Статус ===")
    print(f"Прогресс: {percent:.2f}% ({checked:,}/{total:,})")
    print(f"Скорость: {speed:,} keys/s")
    print(f"Диапазон: {hex(last_range[0])}-{hex(last_range[1])}")
    print(f"================{Colors.END}")

def search_keys(target: str, checked_ranges: List[Dict]) -> Optional[str]:
    total_keys = CONFIG['MAIN_END'] - CONFIG['MAIN_START'] + 1
    start_time = time.time()
    last_status_time = time.time()
    checked_count = sum(r['end']-r['start']+1 for r in checked_ranges)
    found_key = None
    
    with ProcessPoolExecutor(max_workers=CONFIG['MAX_WORKERS'], initializer=init_worker) as executor:
        futures = {}
        
        # Запускаем задачи для всех диапазонов
        for start, end in generate_search_ranges(checked_ranges):
            future = executor.submit(process_range, start, end, target)
            futures[future] = (start, end)
        
        # Обрабатываем результаты
        for future in as_completed(futures):
            start, end = futures[future]
            current_time = time.time()
            
            # Обновляем статистику
            checked_count += end - start + 1
            if current_time - last_status_time > CONFIG['STATUS_INTERVAL']:
                display_status(start_time, checked_count, total_keys, (start, end))
                last_status_time = current_time
            
            # Проверяем результат
            if result := future.result():
                found_key = result[1]
                for f in futures:
                    f.cancel()
                break
            
            # Сохраняем прогресс
            checked_ranges.append({'start': start, 'end': end, 'time': current_time})
            save_checked_ranges(checked_ranges)
    
    return found_key

def main():
    checked_ranges = load_checked_ranges()
    target = CONFIG['TARGET_ADDRESS']
    
    print(f"\n{Colors.CYAN}=== Настройки поиска ===")
    print(f"Целевой адрес: {target}")
    print(f"Приоритетный диапазон: {hex(CONFIG['PRIORITY_START'])}-{hex(CONFIG['PRIORITY_END'])}")
    print(f"Основной диапазон: {hex(CONFIG['MAIN_START'])}-{hex(CONFIG['MAIN_END'])}")
    print(f"Всего ключей: {(CONFIG['MAIN_END']-CONFIG['MAIN_START']+1):,}")
    print(f"Ядер CPU: {CONFIG['MAX_WORKERS']}")
    print(f"============================{Colors.END}\n")
    
    try:
        if found := search_keys(target, checked_ranges):
            print(f"\n{Colors.GREEN}УСПЕХ! Найден ключ:{Colors.END} {found}")
            with open(CONFIG['FOUND_KEYS_FILE'], 'a') as f:
                f.write(f"{time.ctime()}\nKey: {found}\nAddress: {target}\n\n")
        else:
            print(f"\n{Colors.BLUE}Поиск завершен. Ключ не найден.{Colors.END}")
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Поиск прерван.{Colors.END}")
    finally:
        save_checked_ranges(checked_ranges)

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
