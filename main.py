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
    'BATCH_SIZE': 10_000_000,  # 10 миллионов ключей на блок
    'MAX_WORKERS': multiprocessing.cpu_count() * 2,  # Удваиваем процессы
    'STATUS_INTERVAL': 5,
    'TARGET_ADDRESS': "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU",
    'HEX_PATTERNS': ['1a12f1d', '15a3f'],
    'BANNED_PATTERNS': ['aaaa', 'ffff'],
    'CENTER': 0x1A22F1DA9D7000000,  # Центр диапазона
    'SEARCH_RADIUS': 0x10000000  # 268 млн ключей в каждую сторону
}

def init_worker():
    signal.signal(signal.SIGINT, signal.SIG_IGN)

def load_checked_ranges() -> List[Dict]:
    if os.path.exists(CONFIG['CHECKPOINT_FILE']):
        try:
            with open(CONFIG['CHECKPOINT_FILE'], 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"{Colors.RED}Ошибка загрузки чекпоинтов: {e}{Colors.END}")
    return []

def save_checked_ranges(ranges: List[Dict]):
    try:
        with open(CONFIG['CHECKPOINT_FILE'], 'w') as f:
            json.dump(ranges, f, indent=2)
    except Exception as e:
        print(f"{Colors.RED}Ошибка сохранения чекпоинтов: {e}{Colors.END}")

def is_range_checked(start: int, end: int, ranges: List[Dict]) -> bool:
    for r in ranges:
        if r['start'] <= start and r['end'] >= end:
            return True
    return False

def is_valid_key(key: int) -> bool:
    hex_key = hex(key)[2:]
    return (
        any(p in hex_key for p in CONFIG['HEX_PATTERNS']) and
        not any(b in hex_key for b in CONFIG['BANNED_PATTERNS']) and
        7 <= bin(key).count('01') <= 9
    )

@lru_cache(maxsize=1000000)
def private_to_address(private_key_hex: str) -> Optional[str]:
    try:
        priv = bytes.fromhex(private_key_hex)
        if len(priv) != 32:
            return None
        pub = coincurve.PublicKey.from_valid_secret(priv).format(compressed=True)
        h160 = hashlib.new('ripemd160', hashlib.sha256(pub).digest()).digest()
        extended = b'\x00' + h160
        checksum = hashlib.sha256(hashlib.sha256(extended).digest()).digest()[:4]
        return base58.b58encode(extended + checksum).decode('utf-8')
    except Exception as e:
        print(f"{Colors.RED}Ошибка генерации адреса: {e}{Colors.END}")
        return None

def process_range(start: int, end: int, target: str) -> Optional[Tuple[int, str]]:
    processed = 0
    start_time = time.time()
    
    for k in range(start, end + 1):
        if not is_valid_key(k):
            continue
            
        private_key = f"{k:064x}"
        address = private_to_address(private_key)
        processed += 1
        
        if address == target:
            return (k, private_key)
        
        if processed % 100_000 == 0:
            speed = int(processed / (time.time() - start_time))
            print(f"{Colors.CYAN}[PID {os.getpid()}] Проверено: {processed:,} | Скорость: {speed:,} keys/s | Текущий: {hex(k)}{Colors.END}")
    
    return None

def generate_search_ranges(checked_ranges: List[Dict]) -> List[Tuple[int, int]]:
    ranges = []
    center = CONFIG['CENTER']
    radius = CONFIG['SEARCH_RADIUS']
    batch_size = CONFIG['BATCH_SIZE']
    
    # Генерируем блоки в обе стороны от центра
    for direction in [-1, 1]:
        for offset in range(0, radius, batch_size):
            start = center + (direction * offset)
            end = start + (direction * (batch_size - 1))
            
            # Корректируем границы для отрицательного направления
            if direction == -1:
                start, end = end, start
                start, end = end, start  # Меняем местами для правильного порядка
                
            if end > CONFIG['CENTER'] + radius:
                end = CONFIG['CENTER'] + radius
            if start < CONFIG['CENTER'] - radius:
                start = CONFIG['CENTER'] - radius
                
            if not is_range_checked(min(start, end), max(start, end), checked_ranges):
                ranges.append((start, end))
    
    return ranges

def display_status(start_time: float, checked: int, total: int, ranges: List[Tuple[int, int]]):
    elapsed = time.time() - start_time
    percent = (checked / total) * 100
    speed = int(checked / elapsed) if elapsed > 0 else 0
    
    print(f"\n{Colors.YELLOW}=== Статус поиска ===")
    print(f"Прогресс: {percent:.2f}% ({checked:,}/{total:,} ключей)")
    print(f"Скорость: {speed:,} ключей/сек")
    print(f"Затрачено времени: {time.strftime('%H:%M:%S', time.gmtime(elapsed))}")
    print(f"Активные диапазоны:")
    for i, (s, e) in enumerate(ranges[:3]):  # Показываем первые 3 диапазона
        print(f"  {i+1}. {hex(s)} - {hex(e)}")
    if len(ranges) > 3:
        print(f"  ... и ещё {len(ranges)-3} диапазонов")
    print(f"====================={Colors.END}")

def search_keys(target: str, checked_ranges: List[Dict]) -> Optional[str]:
    total_keys = CONFIG['SEARCH_RADIUS'] * 2
    start_time = time.time()
    last_status_time = time.time()
    checked_count = sum(r['end']-r['start']+1 for r in checked_ranges)
    found_key = None
    
    with ProcessPoolExecutor(max_workers=CONFIG['MAX_WORKERS'], initializer=init_worker) as executor:
        futures = {}
        active_ranges = []
        
        while True:
            # Загружаем новые диапазоны для обработки
            new_ranges = generate_search_ranges(checked_ranges)
            if not new_ranges and not futures:
                break  # Все диапазоны проверены
                
            # Добавляем новые задачи
            for start, end in new_ranges:
                if len(futures) >= CONFIG['MAX_WORKERS'] * 2:
                    break
                future = executor.submit(process_range, start, end, target)
                futures[future] = (start, end)
                active_ranges.append((start, end))
                checked_ranges.append({'start': start, 'end': end, 'time': time.time()})
            
            # Проверяем завершенные задачи
            for future in as_completed(futures):
                start, end = futures.pop(future)
                active_ranges.remove((start, end))
                checked_count += end - start + 1
                
                if result := future.result():
                    found_key = result[1]
                    executor.shutdown(wait=False)
                    for f in futures:
                        f.cancel()
                    return found_key
                
                # Обновляем статус
                if time.time() - last_status_time > CONFIG['STATUS_INTERVAL']:
                    display_status(start_time, checked_count, total_keys, active_ranges)
                    save_checked_ranges(checked_ranges)
                    last_status_time = time.time()
            
            time.sleep(0.1)
    
    return None

def main():
    print(f"{Colors.CYAN}\n=== Bitcoin Puzzle 71 Solver ===")
    print(f"Автоматический поиск ключа для адреса: {CONFIG['TARGET_ADDRESS']}")
    print(f"Центр поиска: {hex(CONFIG['CENTER'])}")
    print(f"Радиус: ±{CONFIG['SEARCH_RADIUS']:,} ключей")
    print(f"Размер блока: {CONFIG['BATCH_SIZE']:,} ключей")
    print(f"Процессы: {CONFIG['MAX_WORKERS']}")
    print(f"=============================={Colors.END}\n")
    
    checked_ranges = load_checked_ranges()
    try:
        found_key = search_keys(CONFIG['TARGET_ADDRESS'], checked_ranges)
        if found_key:
            print(f"\n{Colors.GREEN}>>> КЛЮЧ НАЙДЕН! <<<{Colors.END}")
            print(f"Приватный ключ: {found_key}")
            with open(CONFIG['FOUND_KEYS_FILE'], 'a') as f:
                f.write(f"{time.ctime()}\n")
                f.write(f"Адрес: {CONFIG['TARGET_ADDRESS']}\n")
                f.write(f"Ключ: {found_key}\n\n")
        else:
            print(f"\n{Colors.BLUE}Поиск завершен. Ключ не найден в заданном диапазоне.{Colors.END}")
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Поиск прерван пользователем.{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.RED}Критическая ошибка: {e}{Colors.END}")
    finally:
        save_checked_ranges(checked_ranges)
        print(f"{Colors.CYAN}Прогресс сохранен в {CONFIG['CHECKPOINT_FILE']}{Colors.END}")

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
