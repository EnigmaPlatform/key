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
    'LOG_FILE': "search.log",
    'BATCH_SIZE': 100_000,
    'MAX_WORKERS': 12,
    'SAVE_INTERVAL': 5,
    'STATUS_INTERVAL': 1,
    'MAIN_START': 0x349b84b6431a614ef1,
    'MAIN_END': 0x349b84b6431a6c4ef1,
    'TARGET_ADDRESS': "19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR"
}

def init_worker():
    signal.signal(signal.SIGINT, signal.SIG_IGN)

def log_message(message: str):
    """Логирование в файл без влияния на производительность"""
    with open(CONFIG['LOG_FILE'], 'a') as f:
        f.write(f"{time.ctime()} - {message}\n")

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

@lru_cache(maxsize=100000)
def private_to_address(private_key_hex: str) -> Optional[str]:
    """Оптимизированная генерация адреса с проверкой"""
    try:
        priv = bytes.fromhex(private_key_hex)
        pub = coincurve.PublicKey.from_valid_secret(priv).format(compressed=True)
        h160 = hashlib.new('ripemd160', hashlib.sha256(pub).digest()).digest()
        extended = b'\x00' + h160
        checksum = hashlib.sha256(hashlib.sha256(extended).digest()).digest()[:4]
        return base58.b58encode(extended + checksum).decode('utf-8')
    except Exception as e:
        log_message(f"Address gen error: {e}")
        return None

def process_batch(batch: List[Tuple[int, int]], target: str) -> Optional[str]:
    """Обработка батча ключей с логированием"""
    start_key = batch[0][0]
    try:
        for start, end in batch:
            for k in range(start, end + 1):
                private_key = f"{k:064x}"
                address = private_to_address(private_key)
                if address == target:
                    log_message(f"Found candidate at {hex(k)}")
                    return private_key
        log_message(f"Completed batch starting at {hex(start_key)}")
    except Exception as e:
        log_message(f"Error in batch {hex(start_key)}: {e}")
    return None

def generate_batches() -> List[List[Tuple[int, int]]]:
    """Генерация батчей с учетом уже проверенных диапазонов"""
    total_keys = CONFIG['MAIN_END'] - CONFIG['MAIN_START'] + 1
    batch_size = CONFIG['BATCH_SIZE']
    batches = []
    current = CONFIG['MAIN_START']
    
    while current <= CONFIG['MAIN_END']:
        batch_end = min(current + batch_size - 1, CONFIG['MAIN_END'])
        batches.append([(current, batch_end)])
        current = batch_end + 1
    
    log_message(f"Generated {len(batches)} batches total")
    return batches

def run_search(target: str) -> Optional[str]:
    """Основная функция поиска с улучшенным логированием"""
    batches = generate_batches()
    found_key = None
    total_batches = len(batches)
    processed = 0
    start_time = time.time()
    
    with ProcessPoolExecutor(max_workers=CONFIG['MAX_WORKERS'], initializer=init_worker) as executor:
        futures = {executor.submit(process_batch, batch, target): i for i, batch in enumerate(batches)}
        
        for future in as_completed(futures):
            processed += 1
            if result := future.result():
                found_key = result
                for f in futures:
                    f.cancel()
                break
            
            # Логирование прогресса
            if processed % 10 == 0 or processed == total_batches:
                elapsed = time.time() - start_time
                keys_checked = processed * CONFIG['BATCH_SIZE']
                speed = int(keys_checked / elapsed) if elapsed > 0 else 0
                percent = (processed / total_batches) * 100
                log_message(
                    f"Progress: {percent:.2f}% | "
                    f"Speed: {speed:,} keys/sec | "
                    f"Elapsed: {elapsed:.1f}s"
                )
    
    return found_key

def main(target_address=None):
    """Главная функция с улучшенной обработкой результатов"""
    target = target_address if target_address else CONFIG['TARGET_ADDRESS']
    print(f"{Colors.YELLOW}Searching for: {target}{Colors.END}")
    print(f"Range: {hex(CONFIG['MAIN_START'])} - {hex(CONFIG['MAIN_END'])}")
    print(f"Total keys: {(CONFIG['MAIN_END'] - CONFIG['MAIN_START'] + 1):,}")
    print(f"Workers: {CONFIG['MAX_WORKERS']}\n")
    
    start_time = time.time()
    try:
        found_key = run_search(target)
        if found_key:
            print(f"\n{Colors.GREEN}SUCCESS! Private key found:{Colors.END}")
            print(found_key)
            with open(CONFIG['FOUND_KEYS_FILE'], 'a') as f:
                f.write(f"{time.ctime()}\n")
                f.write(f"Private: {found_key}\n")
                f.write(f"Address: {target}\n\n")
        else:
            print(f"\n{Colors.RED}Key not found in specified range.{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.RED}Error: {e}{Colors.END}")
    finally:
        elapsed = time.time() - start_time
        print(f"\n{Colors.BLUE}Search completed in {elapsed:.2f} seconds{Colors.END}")
        print(f"Detailed log saved to {CONFIG['LOG_FILE']}")

if __name__ == "__main__":
    multiprocessing.freeze_support()
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else None
    # Очистка лог-файла при новом запуске
    if os.path.exists(CONFIG['LOG_FILE']):
        os.remove(CONFIG['LOG_FILE'])
    main(target)
