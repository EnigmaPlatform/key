import hashlib
import random
import base58
import time
import json
import os
from tqdm import tqdm
from concurrent.futures import ProcessPoolExecutor, as_completed
import signal
import multiprocessing
import coincurve
import bisect
from typing import List, Dict, Optional

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    END = '\033[0m'

# Конфигурация
CHECKPOINT_FILE = "checked_ranges.json"
FOUND_KEYS_FILE = "found_keys.txt"
CHUNK_SIZE = 10_000_000
MAIN_START = 0x41D6A7E9C0B1D9A9BF
MAIN_END = 0x45FFFFFFFFFFFFFFFFF
BATCH_SIZE = 1_000_000
MAX_WORKERS = multiprocessing.cpu_count() * 2
SAVE_INTERVAL = 5

# Глобальные переменные
stop_flag = False
current_chunk = None
checked_ranges = []

def load_checked_ranges() -> List[Dict]:
    if os.path.exists(CHECKPOINT_FILE):
        try:
            with open(CHECKPOINT_FILE, 'r') as f:
                return json.load(f)
        except:
            return []
    return []

def save_checked_ranges(ranges: List[Dict]):
    with open(CHECKPOINT_FILE, 'w') as f:
        json.dump(ranges, f, indent=2)

def is_range_checked(start: int, end: int) -> bool:
    for r in checked_ranges:
        if r['start'] <= start <= r['end'] or r['start'] <= end <= r['end']:
            return True
    return False

def get_random_chunk() -> Optional[tuple]:
    attempts = 0
    while attempts < 100:
        start = random.randint(MAIN_START, MAIN_END - CHUNK_SIZE)
        end = start + CHUNK_SIZE - 1
        if not is_range_checked(start, end):
            return start, end
        attempts += 1
    return None

def private_to_address(private_key_hex: str) -> Optional[str]:
    try:
        priv = bytes.fromhex(private_key_hex)
        pub = coincurve.PublicKey.from_valid_secret(priv).format(compressed=True)
        h160 = hashlib.new('ripemd160', hashlib.sha256(pub).digest())
        extended = b'\x00' + h160
        checksum = hashlib.sha256(hashlib.sha256(extended).digest()).digest()[:4]
        return base58.b58encode(extended + checksum).decode('utf-8')
    except:
        return None

def process_batch(batch: List[str], target: str) -> Optional[str]:
    for pk in batch:
        if private_to_address(pk) == target:
            return pk
    return None

def check_random_chunk(target: str) -> Optional[str]:
    global current_chunk, checked_ranges
    
    chunk = get_random_chunk()
    if not chunk:
        return None
        
    start, end = chunk
    current_chunk = {'start': start, 'end': end}
    found_key = None
    
    with ProcessPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = []
        for batch_start in range(start, end + 1, BATCH_SIZE):
            batch_end = min(batch_start + BATCH_SIZE - 1, end)
            batch = [format(k, '064x') for k in range(batch_start, batch_end + 1)]
            futures.append(executor.submit(process_batch, batch, target))
        
        for future in as_completed(futures):
            if result := future.result():
                found_key = result
                break
    
    if not found_key:
        checked_ranges.append({'start': start, 'end': end, 'time': time.time()})
        if len(checked_ranges) % SAVE_INTERVAL == 0:
            save_checked_ranges(checked_ranges)
    
    return found_key

def signal_handler(sig, frame):
    global stop_flag
    print(f"\n{Colors.YELLOW}Получен сигнал прерывания...{Colors.END}")
    stop_flag = True

def main(target_address="1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"):
    global stop_flag, checked_ranges
    
    signal.signal(signal.SIGINT, signal_handler)
    checked_ranges = load_checked_ranges()
    total_checked = sum(r['end']-r['start']+1 for r in checked_ranges)
    
    print(f"{Colors.YELLOW}Целевой адрес: {target_address}{Colors.END}")
    print(f"Уже проверено: {total_checked:,} ключей")
    print(f"Размер чанка: {CHUNK_SIZE:,} ключей")
    print(f"Параллельных процессов: {MAX_WORKERS}")
    print(f"Случайный выбор блоков: ВКЛЮЧЕН\n")
    
    try:
        with tqdm(desc="Общий прогресс", unit="key", dynamic_ncols=True) as pbar:
            while not stop_flag:
                if found_key := check_random_chunk(target_address):
                    print(f"\n{Colors.GREEN}Ключ найден!{Colors.END}")
                    print(f"Приватный ключ: {found_key}")
                    with open(FOUND_KEYS_FILE, 'a') as f:
                        f.write(f"{time.ctime()}\n")
                        f.write(f"Private: {found_key}\n")
                        f.write(f"Address: {target_address}\n\n")
                    break
                pbar.update(CHUNK_SIZE)
                
    except Exception as e:
        print(f"\n{Colors.RED}Ошибка: {e}{Colors.END}")
    finally:
        save_checked_ranges(checked_ranges)
        total = sum(r['end']-r['start']+1 for r in checked_ranges)
        print(f"\n{Colors.YELLOW}Итоги:{Colors.END}")
        print(f"Всего проверено: {total:,} ключей")
        print(f"Осталось: {MAIN_END - MAIN_START + 1 - total:,} ключей")

if __name__ == "__main__":
    import sys
    main(sys.argv[1] if len(sys.argv) > 1 else "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU")
