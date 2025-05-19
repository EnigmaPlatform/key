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
from typing import List, Dict, Optional

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    END = '\033[0m'

# Конфигурация (увеличена CHUNK_SIZE до 100 млн)
CHECKPOINT_FILE = "checked_ranges.json"
FOUND_KEYS_FILE = "found_keys.txt"
CHUNK_SIZE = 100_000_000  # Увеличенный размер чанка
MIN_CHUNK_SIZE = 10_000_000  # Минимальный допустимый размер чанка
MAIN_START = 0x349b84b6430a6c4ef1
MAIN_END = 0x349b84b6431a6c4ef1
BATCH_SIZE = 10_000_000  # Увеличен для соответствия
MAX_WORKERS = min(32, (os.cpu_count() or 1) * 2)
SAVE_INTERVAL = 5
STATUS_INTERVAL = 60

def init_worker():
    signal.signal(signal.SIGINT, signal.SIG_IGN)

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

def is_range_checked(start: int, end: int, ranges: List[Dict]) -> bool:
    for r in ranges:
        if r['start'] <= start <= r['end'] or r['start'] <= end <= r['end']:
            return True
    return False

def get_random_chunk(ranges: List[Dict]) -> Optional[tuple]:
    attempts = 0
    while attempts < 100:
        # Вычисляем доступный диапазон
        available_range = MAIN_END - MAIN_START - sum(
            r['end'] - r['start'] + 1 for r in ranges
        )
        
        # Если осталось меньше CHUNK_SIZE, берем меньший чанк (но не меньше MIN_CHUNK_SIZE)
        current_chunk_size = min(CHUNK_SIZE, max(available_range, MIN_CHUNK_SIZE))
        
        if available_range <= 0:
            return None
            
        start = random.randint(MAIN_START, MAIN_END - current_chunk_size)
        end = start + current_chunk_size - 1
        
        if not is_range_checked(start, end, ranges):
            return start, end
        attempts += 1
    return None

def private_to_address(private_key_hex: str) -> Optional[str]:
    try:
        priv = bytes.fromhex(private_key_hex)
        pub = coincurve.PublicKey.from_valid_secret(priv).format(compressed=True)
        h160 = hashlib.new('ripemd160', hashlib.sha256(pub).digest())
        extended = b'\x00' + h160
        checksum = hashlib.sha256(hashlib.sha256(extended).digest())[:4]
        return base58.b58encode(extended + checksum).decode('utf-8')
    except:
        return None

def process_batch(batch: List[str], target: str) -> Optional[str]:
    for pk in batch:
        if private_to_address(pk) == target:
            return pk
    return None

def check_random_chunk(target: str, ranges: List[Dict]) -> Optional[str]:
    chunk = get_random_chunk(ranges)
    if not chunk:
        return None
        
    start, end = chunk
    chunk_size = end - start + 1
    print(f"\n{Colors.YELLOW}Текущий диапазон: {hex(start)} - {hex(end)} ({chunk_size:,} ключей){Colors.END}")
    
    found_key = None
    try:
        with ProcessPoolExecutor(max_workers=MAX_WORKERS, initializer=init_worker) as executor:
            futures = []
            for batch_start in range(start, end + 1, BATCH_SIZE):                    
                batch_end = min(batch_start + BATCH_SIZE - 1, end)
                batch = [format(k, '064x') for k in range(batch_start, batch_end + 1)]
                futures.append(executor.submit(process_batch, batch, target))
            
            for future in as_completed(futures):                    
                if result := future.result():
                    found_key = result
                    executor.shutdown(wait=False)
                    break
    
    except Exception as e:
        print(f"\n{Colors.RED}Ошибка: {e}{Colors.END}")
        return None
    
    if not found_key:
        ranges.append({'start': start, 'end': end, 'time': time.time()})
        if len(ranges) % SAVE_INTERVAL == 0:
            save_checked_ranges(ranges)
    
    return found_key

def show_status(checked: List[Dict]):
    if not checked:
        print(f"{Colors.YELLOW}Еще не проверено ни одного диапазона{Colors.END}")
        return
    
    total_checked = sum(r['end']-r['start']+1 for r in checked)
    total_range = MAIN_END - MAIN_START + 1
    percent = (total_checked / total_range) * 100 if total_range > 0 else 0
    
    print(f"\n{Colors.YELLOW}=== Статус проверки ===")
    print(f"Проверено: {total_checked:,} ключей")
    print(f"Прогресс: {percent:.6f}%")
    print(f"Осталось: {max(0, total_range - total_checked):,} ключей")
    if checked:
        last_chunk = checked[-1]
        print(f"Последний диапазон: {hex(last_chunk['start'])} - {hex(last_chunk['end'])} ({last_chunk['end']-last_chunk['start']+1:,} keys)")
    print(f"========================={Colors.END}\n")

def main(target_address="19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR"):
    checked_ranges = load_checked_ranges()
    last_status_time = time.time()
    total_range = MAIN_END - MAIN_START + 1
    
    print(f"{Colors.YELLOW}Целевой адрес: {target_address}{Colors.END}")
    print(f"Диапазон поиска: {hex(MAIN_START)} - {hex(MAIN_END)}")
    print(f"Общий размер: {total_range:,} ключей")
    print(f"Размер чанка: {CHUNK_SIZE:,} ключей (авторегулировка)")
    print(f"Мин. размер чанка: {MIN_CHUNK_SIZE:,} ключей")
    print(f"Параллельных процессов: {MAX_WORKERS}\n")
    
    try:
        with tqdm(total=total_range, desc="Общий прогресс", unit="key", 
                 dynamic_ncols=True, mininterval=1) as pbar:
            while True:
                current_time = time.time()
                if current_time - last_status_time > STATUS_INTERVAL:
                    show_status(checked_ranges)
                    last_status_time = current_time
                
                if found_key := check_random_chunk(target_address, checked_ranges):
                    print(f"\n{Colors.GREEN}Ключ найден!{Colors.END}")
                    print(f"Приватный ключ: {found_key}")
                    with open(FOUND_KEYS_FILE, 'a') as f:
                        f.write(f"{time.ctime()}\n")
                        f.write(f"Private: {found_key}\n")
                        f.write(f"Address: {target_address}\n\n")
                    break
                
                # Обновляем прогресс-бар
                if checked_ranges:
                    pbar.n = sum(r['end']-r['start']+1 for r in checked_ranges)
                    pbar.refresh()
                
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Прерывание пользователем...{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.RED}Ошибка: {e}{Colors.END}")
    finally:
        save_checked_ranges(checked_ranges)
        show_status(checked_ranges)

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
