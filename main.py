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
    END = '\033[0m'

CONFIG = {
    'CHECKPOINT_FILE': "checked_ranges.json",
    'FOUND_KEYS_FILE': "found_keys.txt",
    'BATCH_SIZE': 1_000_000,
    'MAX_WORKERS': 12,
    'SAVE_INTERVAL': 5,
    'STATUS_INTERVAL': 5,
    'MAIN_START': 0x349b84b64311614ef1,
    'MAIN_END': 0x349b84b6431a6c4ef1,
    'TARGET_ADDRESS': "19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR"
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
    with open(CONFIG['CHECKPOINT_FILE'], 'w') as f:
        json.dump(ranges, f, indent=2)

def generate_bitcoin_address(private_key_hex: str) -> str:
    """Генерация Bitcoin-адреса из приватного ключа с проверкой каждой операции"""
    try:
        # Конвертация приватного ключа
        priv_bytes = bytes.fromhex(private_key_hex)
        
        # Генерация публичного ключа (сжатый формат)
        public_key = coincurve.PublicKey.from_valid_secret(priv_bytes).format(compressed=True)
        
        # SHA-256
        sha256_hash = hashlib.sha256(public_key).digest()
        
        # RIPEMD-160
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_hash)
        ripemd160_hash = ripemd160.digest()
        
        # Добавление версионного байта (0x00 для mainnet)
        versioned_payload = b'\x00' + ripemd160_hash
        
        # Первый SHA-256
        first_sha = hashlib.sha256(versioned_payload).digest()
        
        # Второй SHA-256 для контрольной суммы
        checksum = hashlib.sha256(first_sha).digest()[:4]
        
        # Полный payload
        full_payload = versioned_payload + checksum
        
        # Кодирование в Base58
        return base58.b58encode(full_payload).decode('utf-8')
    except Exception as e:
        print(f"{Colors.RED}Address generation error: {e}{Colors.END}")
        return ""

def process_batch(batch: List[str], target: str) -> Optional[str]:
    """Обработка батча ключей"""
    for pk in batch:
        address = generate_bitcoin_address(pk)
        if address == target:
            return pk
    return None

def generate_key_batches(start: int, end: int) -> List[List[str]]:
    """Генерация батчей ключей для проверки"""
    batch_size = CONFIG['BATCH_SIZE']
    batches = []
    current = max(start, CONFIG['MAIN_START'])
    end = min(end, CONFIG['MAIN_END'])
    
    while current <= end:
        batch_end = min(current + batch_size - 1, end)
        batches.append([f"{k:064x}" for k in range(current, batch_end + 1)])
        current = batch_end + 1
    
    return batches

def balanced_search(target: str, checked_ranges: List[Dict]) -> Optional[str]:
    """Балансированный поиск с разделением диапазона"""
    total_range = CONFIG['MAIN_END'] - CONFIG['MAIN_START']
    workers = CONFIG['MAX_WORKERS']
    mid = CONFIG['MAIN_START'] + total_range // 2
    chunk_size = total_range // workers
    
    # Создаем диапазоны для каждого worker'а
    ranges = []
    for i in range(workers):
        if i % 2 == 0:
            # Правая сторона от середины
            start = mid + (i//2) * chunk_size
            end = start + chunk_size - 1
        else:
            # Левая сторона от середины
            end = mid - (i//2) * chunk_size - 1
            start = end - chunk_size + 1
        
        # Корректировка границ
        start = max(start, CONFIG['MAIN_START'])
        end = min(end, CONFIG['MAIN_END'])
        if start <= end:
            ranges.append((start, end))
    
    found_key = None
    with ProcessPoolExecutor(max_workers=workers, initializer=init_worker) as executor:
        futures = {}
        for start, end in ranges:
            batches = generate_key_batches(start, end)
            for batch in batches:
                future = executor.submit(process_batch, batch, target)
                futures[future] = (start, end)
        
        for future in as_completed(futures):
            if result := future.result():
                found_key = result
                # Отменяем все остальные задачи
                for f in futures:
                    f.cancel()
                break
    
    if not found_key:
        # Сохраняем проверенные диапазоны
        checked_ranges.extend([{'start': start, 'end': end, 'time': time.time()} 
                             for start, end in ranges])
        if len(checked_ranges) % CONFIG['SAVE_INTERVAL'] == 0:
            save_checked_ranges(checked_ranges)
    
    return found_key

def format_keys(n: int) -> str:
    """Форматирование больших чисел"""
    for unit in ['', 'K', 'M', 'B', 'T']:
        if abs(n) < 1000:
            return f"{n:,.0f}{unit}"
        n /= 1000
    return f"{n:,.0f}P"

def show_progress(checked: List[Dict], start_time: float):
    """Отображение прогресса"""
    total_checked = sum(r['end']-r['start']+1 for r in checked) if checked else 0
    total_range = CONFIG['MAIN_END'] - CONFIG['MAIN_START'] + 1
    elapsed = time.time() - start_time
    keys_per_sec = total_checked / elapsed if elapsed > 0 else 0
    percent = (total_checked / total_range) * 100 if total_range > 0 else 0
    
    print(f"\n{Colors.YELLOW}=== Status ===")
    print(f"Checked: {format_keys(total_checked)} keys")
    print(f"Progress: {percent:.8f}%")
    print(f"Speed: {format_keys(int(keys_per_sec))} keys/sec")
    print(f"Elapsed: {elapsed:.1f}s")
    if checked:
        print(f"Last range: {hex(checked[-1]['start'])} - {hex(checked[-1]['end'])}")
    print(f"=================={Colors.END}")

def main(target_address=None):
    """Основная функция"""
    checked_ranges = load_checked_ranges()
    start_time = time.time()
    last_status_time = time.time()
    target = target_address if target_address else CONFIG['TARGET_ADDRESS']
    
    print(f"{Colors.YELLOW}Target address: {target}{Colors.END}")
    print(f"Search range: {hex(CONFIG['MAIN_START'])} - {hex(CONFIG['MAIN_END'])}")
    print(f"Total keys: {format_keys(CONFIG['MAIN_END'] - CONFIG['MAIN_START'] + 1)}")
    print(f"Workers: {CONFIG['MAX_WORKERS']}\n")
    
    try:
        while True:
            current_time = time.time()
            if current_time - last_status_time > CONFIG['STATUS_INTERVAL']:
                show_progress(checked_ranges, start_time)
                last_status_time = current_time
            
            found_key = balanced_search(target, checked_ranges)
            if found_key:
                print(f"\n{Colors.GREEN}SUCCESS: Key found!{Colors.END}")
                print(f"Private key: {found_key}")
                with open(CONFIG['FOUND_KEYS_FILE'], 'a') as f:
                    f.write(f"{time.ctime()}\n")
                    f.write(f"Private: {found_key}\n")
                    f.write(f"Address: {target}\n\n")
                break
            
            # Проверка завершения
            remaining = CONFIG['MAIN_END'] - CONFIG['MAIN_START'] + 1 - sum(
                r['end']-r['start']+1 for r in checked_ranges)
            if remaining <= 0:
                print(f"\n{Colors.BLUE}COMPLETE: Entire range checked.{Colors.END}")
                print(f"{Colors.YELLOW}Key not found in specified range.{Colors.END}")
                break
                
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Search interrupted.{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.RED}Error: {e}{Colors.END}")
    finally:
        save_checked_ranges(checked_ranges)
        show_progress(checked_ranges, start_time)

if __name__ == "__main__":
    multiprocessing.freeze_support()
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else None
    main(target)
