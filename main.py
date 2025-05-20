import hashlib
import random
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

# Конфигурация
CONFIG = {
    'CHECKPOINT_FILE': "checked_ranges.json",
    'FOUND_KEYS_FILE': "found_keys.txt",
    'CHUNK_SIZE': 10_000_000,
    'MIN_CHUNK_SIZE': 1,
    'MAIN_START': 0x1A12F1DA9D7000000,
    'MAIN_END': 0x1C0000000000000000,
    'BATCH_SIZE': 1_000_000,
    'MAX_WORKERS': 12,
    'SAVE_INTERVAL': 5,
    'STATUS_INTERVAL': 5,
    'TARGET_ADDRESS': "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"
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

def is_range_checked(start: int, end: int, ranges: List[Dict]) -> bool:
    return any(r['start'] <= start <= r['end'] or r['start'] <= end <= r['end'] for r in ranges)

def get_unverified_ranges(ranges: List[Dict]) -> List[Tuple[int, int]]:
    sorted_ranges = sorted(ranges, key=lambda x: x['start'])
    unverified = []
    last_end = CONFIG['MAIN_START'] - 1
    
    for r in sorted_ranges:
        if r['start'] > last_end + 1:
            unverified.append((last_end + 1, r['start'] - 1))
        last_end = max(last_end, r['end'])
    
    if last_end < CONFIG['MAIN_END']:
        unverified.append((last_end + 1, CONFIG['MAIN_END']))
    
    return unverified

def get_random_chunk(ranges: List[Dict]) -> Optional[Tuple[int, int]]:
    unverified = get_unverified_ranges(ranges)
    if not unverified:
        return None
    
    range_start, range_end = random.choice(unverified)
    range_size = range_end - range_start + 1
    
    if range_size <= CONFIG['CHUNK_SIZE'] * 2:
        return range_start, range_end
    
    adaptive_size = min(CONFIG['CHUNK_SIZE'], max(CONFIG['MIN_CHUNK_SIZE'], range_size // 10))
    start = random.randint(range_start, range_end - adaptive_size + 1)
    return start, start + adaptive_size - 1

@lru_cache(maxsize=1000000)
def private_to_address(private_key_hex: str) -> Optional[str]:
    try:
        # Конвертируем приватный ключ в байты
        priv = bytes.fromhex(private_key_hex)
        
        # Генерируем публичный ключ (сжатый формат)
        pub_key = coincurve.PublicKey.from_valid_secret(priv).format(compressed=True)
        
        # SHA-256 хеш публичного ключа
        sha256_hash = hashlib.sha256(pub_key).digest()
        
        # RIPEMD-160 хеш от SHA-256
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_hash)
        ripemd160_hash = ripemd160.digest()
        
        # Добавляем версионный байт (0x00 для Mainnet)
        versioned_payload = b'\x00' + ripemd160_hash
        
        # Вычисляем контрольную сумму (первые 4 байта двойного SHA-256)
        first_sha = hashlib.sha256(versioned_payload).digest()
        checksum = hashlib.sha256(first_sha).digest()[:4]
        
        # Собираем полный payload
        full_payload = versioned_payload + checksum
        
        # Кодируем в Base58
        return base58.b58encode(full_payload).decode('utf-8')
    except Exception as e:
        print(f"{Colors.RED}Error generating address: {e}{Colors.END}")
        return None

def process_batch(batch: List[str], target: str) -> Optional[str]:
    for pk in batch:
        address = private_to_address(pk)
        if address == target:
            return pk
    return None

def generate_batches(start: int, end: int) -> List[List[str]]:
    batch_size = CONFIG['BATCH_SIZE']
    batches = []
    current = start
    
    while current <= end:
        batch_end = min(current + batch_size - 1, end)
        batch = [f"{k:064x}" for k in range(current, batch_end + 1)]
        batches.append(batch)
        current = batch_end + 1
    
    return batches

def check_random_chunk(target: str, ranges: List[Dict]) -> Optional[str]:
    chunk = get_random_chunk(ranges)
    if not chunk:
        return None
        
    start, end = chunk
    chunk_size = end - start + 1
    print(f"\n{Colors.YELLOW}Current range: {hex(start)} - {hex(end)} ({chunk_size:,} keys){Colors.END}")
    
    found_key = None
    try:
        batches = generate_batches(start, end)
        with ProcessPoolExecutor(max_workers=CONFIG['MAX_WORKERS'], initializer=init_worker) as executor:
            futures = {executor.submit(process_batch, batch, target): batch for batch in batches}
            
            for future in as_completed(futures):
                if result := future.result():
                    found_key = result
                    for f in futures:
                        f.cancel()
                    break
    
    except Exception as e:
        print(f"\n{Colors.RED}Error in process pool: {e}{Colors.END}")
        return None
    
    if not found_key:
        ranges.append({'start': start, 'end': end, 'time': time.time()})
        if len(ranges) % CONFIG['SAVE_INTERVAL'] == 0:
            save_checked_ranges(ranges)
    
    return found_key

def format_large_number(n: int) -> str:
    for unit in ['', 'K', 'M', 'B', 'T']:
        if abs(n) < 1000:
            return f"{n:,.0f}{unit}"
        n /= 1000
    return f"{n:,.0f}P"

def show_status(checked: List[Dict]):
    if not checked:
        print(f"{Colors.YELLOW}No ranges checked yet{Colors.END}")
        return
    
    total_checked = sum(r['end']-r['start']+1 for r in checked)
    total_range = CONFIG['MAIN_END'] - CONFIG['MAIN_START'] + 1
    percent = (total_checked / total_range) * 100 if total_range > 0 else 0
    
    print(f"\n{Colors.YELLOW}=== Status ===")
    print(f"Checked: {format_large_number(total_checked)} keys")
    print(f"Progress: {percent:.12f}%")
    print(f"Remaining: {format_large_number(max(0, total_range - total_checked))} keys")
    if checked:
        print(f"Last range: {hex(checked[-1]['start'])} - {hex(checked[-1]['end'])}")
    print(f"=================={Colors.END}")

def show_final_stats(checked: List[Dict], start_time: float):
    total_checked = sum(r['end']-r['start']+1 for r in checked) if checked else 0
    elapsed = time.time() - start_time
    keys_per_sec = total_checked / elapsed if elapsed > 0 else 0
    
    print(f"\n{Colors.BLUE}=== FINAL RESULTS ===")
    print(f"Total keys checked: {format_large_number(total_checked)}")
    print(f"Total time: {elapsed:.2f} seconds")
    print(f"Average speed: {format_large_number(int(keys_per_sec))} keys/sec")
    if checked:
        print(f"Last checked range: {hex(checked[-1]['start'])} - {hex(checked[-1]['end'])}")
    print(f"===================={Colors.END}")

def main(target_address=None):
    checked_ranges = load_checked_ranges()
    last_status_time = time.time()
    total_range = CONFIG['MAIN_END'] - CONFIG['MAIN_START'] + 1
    start_time = time.time()
    
    target = target_address if target_address else CONFIG['TARGET_ADDRESS']
    print(f"{Colors.YELLOW}Target address: {target}{Colors.END}")
    print(f"Search range: {hex(CONFIG['MAIN_START'])} - {hex(CONFIG['MAIN_END'])}")
    print(f"Total keys: {format_large_number(total_range)}")
    print(f"Chunk size: {format_large_number(CONFIG['CHUNK_SIZE'])} (auto-adjusted)")
    print(f"Min chunk size: {CONFIG['MIN_CHUNK_SIZE']}")
    print(f"Workers: {CONFIG['MAX_WORKERS']}\n")
    
    try:
        found_key = None
        while True:
            current_time = time.time()
            if current_time - last_status_time > CONFIG['STATUS_INTERVAL']:
                total_checked = sum(r['end']-r['start']+1 for r in checked_ranges)
                elapsed = current_time - start_time
                keys_per_sec = total_checked / elapsed if elapsed > 0 else 0
                
                print(f"\n{Colors.YELLOW}[Progress] Checked: {format_large_number(total_checked)} keys | "
                      f"Speed: {format_large_number(int(keys_per_sec))} keys/sec | "
                      f"Elapsed: {elapsed:.1f}s{Colors.END}")
                show_status(checked_ranges)
                last_status_time = current_time
            
            result = check_random_chunk(target, checked_ranges)
            if result:
                found_key = result
                break
            
            # Проверка завершения полного перебора
            unverified = get_unverified_ranges(checked_ranges)
            if not unverified:
                break
        
        if found_key:
            print(f"\n{Colors.GREEN}SUCCESS: Key found!{Colors.END}")
            print(f"Private key: {found_key}")
            with open(CONFIG['FOUND_KEYS_FILE'], 'a') as f:
                f.write(f"{time.ctime()}\n")
                f.write(f"Private: {found_key}\n")
                f.write(f"Address: {target}\n\n")
        else:
            print(f"\n{Colors.BLUE}COMPLETE: Entire range has been checked.{Colors.END}")
            print(f"{Colors.YELLOW}The target key was not found in the specified range.{Colors.END}")
        
        show_final_stats(checked_ranges, start_time)
                
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Interrupted by user{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.RED}Error: {e}{Colors.END}")
    finally:
        save_checked_ranges(checked_ranges)
        show_status(checked_ranges)
        show_final_stats(checked_ranges, start_time)

if __name__ == "__main__":
    import sys
    multiprocessing.freeze_support()
    target_addr = sys.argv[1] if len(sys.argv) > 1 else None
    main(target_addr)
