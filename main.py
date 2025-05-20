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
    'MAX_WORKERS': 12,
    'STATUS_INTERVAL': 1,
    'MAIN_START': 0x349b84b6431a6b4ef1,
    'MAIN_END': 0x349b84b6431a6c4ef1,
    'TARGET_ADDRESS': "19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR"
}

def init_worker():
    signal.signal(signal.SIGINT, signal.SIG_IGN)

def load_checked_ranges() -> List[Dict]:
    if os.path.exists(CONFIG['CHECKPOINT_FILE']):
        try:
            with open(CONFIG['CHECKPOINT_FILE'], 'r') as f:
                data = json.load(f)
                print(f"{Colors.CYAN}Loaded {len(data)} checked ranges from file{Colors.END}")
                return data
        except Exception as e:
            print(f"{Colors.RED}Error loading checkpoints: {e}{Colors.END}")
    return []

def save_checked_ranges(ranges: List[Dict]):
    try:
        with open(CONFIG['CHECKPOINT_FILE'], 'w') as f:
            json.dump(ranges, f, indent=2)
    except Exception as e:
        print(f"{Colors.RED}Error saving checkpoints: {e}{Colors.END}")

def is_range_checked(start: int, end: int, ranges: List[Dict]) -> bool:
    for r in ranges:
        if r['start'] <= start and r['end'] >= end:
            return True
    return False

@lru_cache(maxsize=100000)
def private_to_address(private_key_hex: str) -> Optional[str]:
    try:
        priv = bytes.fromhex(private_key_hex)
        pub = coincurve.PublicKey.from_valid_secret(priv).format(compressed=True)
        h160 = hashlib.new('ripemd160', hashlib.sha256(pub).digest()).digest()
        extended = b'\x00' + h160
        checksum = hashlib.sha256(hashlib.sha256(extended).digest()).digest()[:4]
        return base58.b58encode(extended + checksum).decode('utf-8')
    except Exception as e:
        print(f"{Colors.RED}Address gen error: {e}{Colors.END}")
        return None

def process_range(start: int, end: int, target: str) -> Optional[str]:
    """Обрабатывает диапазон ключей и возвращает найденный ключ"""
    for k in range(start, end + 1):
        private_key = f"{k:064x}"
        address = private_to_address(private_key)
        if address == target:
            return private_key
    return None

def generate_search_ranges(checked_ranges: List[Dict]) -> List[Tuple[int, int]]:
    """Генерирует непроверенные диапазоны с учетом сохраненных данных"""
    total_range = CONFIG['MAIN_END'] - CONFIG['MAIN_START'] + 1
    workers = CONFIG['MAX_WORKERS']
    chunk_size = total_range // workers
    ranges = []
    
    for i in range(workers):
        start = CONFIG['MAIN_START'] + i * chunk_size
        end = start + chunk_size - 1 if i < workers - 1 else CONFIG['MAIN_END']
        
        if not is_range_checked(start, end, checked_ranges):
            ranges.append((start, end))
    
    return ranges

def display_status(start_time: float, checked_count: int, last_range: Tuple[int, int] = None):
    """Выводит текущую статистику в терминал"""
    elapsed = time.time() - start_time
    total_keys = CONFIG['MAIN_END'] - CONFIG['MAIN_START'] + 1
    percent = (checked_count / total_keys) * 100
    speed = int(checked_count / elapsed) if elapsed > 0 else 0
    
    print(f"\n{Colors.YELLOW}=== Поиск активен ===")
    print(f"Проверено: {checked_count:,} ключей ({percent:.2f}%)")
    print(f"Скорость: {speed:,} ключей/сек")
    print(f"Затрачено времени: {elapsed:.1f}s")
    if last_range:
        print(f"Текущий диапазон: {hex(last_range[0])} - {hex(last_range[1])}")
    print(f"===================={Colors.END}")

def search_keys(target: str, checked_ranges: List[Dict]) -> Optional[str]:
    """Основная функция поиска с сохранением прогресса"""
    search_ranges = generate_search_ranges(checked_ranges)
    if not search_ranges:
        print(f"{Colors.BLUE}Все диапазоны уже проверены{Colors.END}")
        return None
    
    start_time = time.time()
    last_status_time = time.time()
    found_key = None
    checked_count = sum(r['end']-r['start']+1 for r in checked_ranges)
    
    with ProcessPoolExecutor(max_workers=CONFIG['MAX_WORKERS'], initializer=init_worker) as executor:
        futures = {}
        
        # Запускаем задачи для всех непроверенных диапазонов
        for start, end in search_ranges:
            future = executor.submit(process_range, start, end, target)
            futures[future] = (start, end)
        
        # Обрабатываем результаты
        for future in as_completed(futures):
            start, end = futures[future]
            current_time = time.time()
            
            # Обновляем статистику
            if current_time - last_status_time > CONFIG['STATUS_INTERVAL']:
                checked_count += end - start + 1
                display_status(start_time, checked_count, (start, end))
                last_status_time = current_time
            
            # Проверяем результат
            if result := future.result():
                found_key = result
                # Отменяем все остальные задачи
                for f in futures:
                    f.cancel()
                break
            
            # Сохраняем проверенный диапазон
            checked_ranges.append({'start': start, 'end': end, 'time': current_time})
            if len(checked_ranges) % 10 == 0:  # Сохраняем каждые 10 диапазонов
                save_checked_ranges(checked_ranges)
    
    # Финализируем сохранение
    save_checked_ranges(checked_ranges)
    return found_key

def main(target_address=None):
    """Главная функция с обработкой аргументов"""
    target = target_address if target_address else CONFIG['TARGET_ADDRESS']
    checked_ranges = load_checked_ranges()
    
    print(f"\n{Colors.CYAN}=== Начало поиска ===")
    print(f"Целевой адрес: {target}")
    print(f"Диапазон: {hex(CONFIG['MAIN_START'])} - {hex(CONFIG['MAIN_END'])}")
    print(f"Всего ключей: {(CONFIG['MAIN_END'] - CONFIG['MAIN_START'] + 1):,}")
    print(f"Рабочих процессов: {CONFIG['MAX_WORKERS']}")
    print(f"========================={Colors.END}\n")
    
    try:
        found_key = search_keys(target, checked_ranges)
        if found_key:
            print(f"\n{Colors.GREEN}НАЙДЕН КЛЮЧ!{Colors.END}")
            print(f"Приватный ключ: {found_key}")
            with open(CONFIG['FOUND_KEYS_FILE'], 'a') as f:
                f.write(f"{time.ctime()}\n")
                f.write(f"Private: {found_key}\n")
                f.write(f"Address: {target}\n\n")
        else:
            print(f"\n{Colors.BLUE}Поиск завершен. Ключ не найден.{Colors.END}")
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Поиск прерван пользователем.{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.RED}Ошибка: {e}{Colors.END}")
    finally:
        save_checked_ranges(checked_ranges)

if __name__ == "__main__":
    multiprocessing.freeze_support()
    import sys
    target_addr = sys.argv[1] if len(sys.argv) > 1 else None
    main(target_addr)
