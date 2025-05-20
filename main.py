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

CONFIG = {
    'CHECKPOINT_FILE': "checked_ranges.json",
    'FOUND_KEYS_FILE': "found_keys.txt",
    'CHUNK_SIZE': 10_000_000,
    'MIN_CHUNK_SIZE': 1,
    'MAIN_START': 0x349b84b64311614ef1,
    'MAIN_END': 0x349b84b6431a6c4ef1,
    'BATCH_SIZE': 1_000_000,
    'MAX_WORKERS': 12,
    'SAVE_INTERVAL': 5,
    'STATUS_INTERVAL': 5,
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

@lru_cache(maxsize=1000000)
def private_to_address(private_key_hex: str) -> Optional[str]:
    try:
        priv = bytes.fromhex(private_key_hex)
        pub_key = coincurve.PublicKey.from_valid_secret(priv).format(compressed=True)
        sha256_hash = hashlib.sha256(pub_key).digest()
        
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_hash)
        ripemd160_hash = ripemd160.digest()
        
        versioned_payload = b'\x00' + ripemd160_hash
        first_sha = hashlib.sha256(versioned_payload).digest()
        checksum = hashlib.sha256(first_sha).digest()[:4]
        
        full_payload = versioned_payload + checksum
        return base58.b58encode(full_payload).decode('utf-8')
    except Exception as e:
        print(f"{Colors.RED}Error generating address: {e}{Colors.END}")
        return None

def process_range(start: int, end: int, target: str) -> Optional[str]:
    batch_size = CONFIG['BATCH_SIZE']
    current = max(start, CONFIG['MAIN_START'])
    end = min(end, CONFIG['MAIN_END'])
    
    while current <= end:
        batch_end = min(current + batch_size - 1, end)
        batch = [f"{k:064x}" for k in range(current, batch_end + 1)]
        
        for pk in batch:
            address = private_to_address(pk)
            if address == target:
                return pk
        current = batch_end + 1
    return None

def generate_search_ranges() -> List[Tuple[int, int]]:
    start = CONFIG['MAIN_START']
    end = CONFIG['MAIN_END']
    workers = CONFIG['MAX_WORKERS']
    mid = (start + end) // 2
    chunk_size = (end - start) // workers
    
    ranges = []
    for i in range(workers):
        if i % 2 == 0:
            # Правая сторона от середины
            range_start = mid + (i//2)*chunk_size
            range_end = mid + ((i//2)+1)*chunk_size - 1
        else:
            # Левая сторона от середины
            range_start = mid - ((i//2)+1)*chunk_size
            range_end = mid - (i//2)*chunk_size - 1
        
        range_start = max(range_start, start)
        range_end = min(range_end, end)
        if range_start <= range_end:
            ranges.append((range_start, range_end))
    
    return ranges

def balanced_search(target: str, checked_ranges: List[Dict]) -> Optional[str]:
    search_ranges = generate_search_ranges()
    found_key = None
    
    with ProcessPoolExecutor(max_workers=CONFIG['MAX_WORKERS'], initializer=init_worker) as executor:
        futures = {executor.submit(process_range, r[0], r[1], target): r for r in search_ranges}
        
        for future in as_completed(futures):
            if result := future.result():
                found_key = result
                # Отменить все остальные задачи
                for f in futures:
                    f.cancel()
                break
    
    if not found_key:
        # Сохраняем проверенные диапазоны
        checked_ranges.extend([{'start': r[0], 'end': r[1], 'time': time.time()} 
                             for r in search_ranges])
        if len(checked_ranges) % CONFIG['SAVE_INTERVAL'] == 0:
            save_checked_ranges(checked_ranges)
    
    return found_key

def format_large_number(n: int) -> str:
    for unit in ['', 'K', 'M', 'B', 'T']:
        if abs(n) < 1000:
            return f"{n:,.0f}{unit}"
        n /= 1000
    return f"{n:,.0f}P"

def show_progress(checked: List[Dict], start_time: float):
    total_checked = sum(r['end']-r['start']+1 for r in checked) if checked else 0
    total_range = CONFIG['MAIN_END'] - CONFIG['MAIN_START'] + 1
    elapsed = time.time() - start_time
    keys_per_sec = total_checked / elapsed if elapsed > 0 else 0
    percent = (total_checked / total_range) * 100 if total_range > 0 else 0
    
    print(f"\n{Colors.YELLOW}=== Status ===")
    print(f"Checked: {format_large_number(total_checked)} keys")
    print(f"Progress: {percent:.8f}%")
    print(f"Speed: {format_large_number(int(keys_per_sec))} keys/sec")
    print(f"Elapsed: {elapsed:.1f}s")
    if checked:
        print(f"Last range: {hex(checked[-1]['start'])} - {hex(checked[-1]['end'])}")
    print(f"=================={Colors.END}")

def main(target_address=None):
    checked_ranges = load_checked_ranges()
    start_time = time.time()
    last_status_time = time.time()
    
    target = target_address if target_address else CONFIG['TARGET_ADDRESS']
    print(f"{Colors.YELLOW}Target address: {target}{Colors.END}")
    print(f"Search range: {hex(CONFIG['MAIN_START'])} - {hex(CONFIG['MAIN_END'])}")
    print(f"Total keys: {format_large_number(CONFIG['MAIN_END'] - CONFIG['MAIN_START'] + 1)}")
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
            
            # Проверяем, остались ли непроверенные диапазоны
            all_checked = True
            for r in generate_search_ranges():
                if not any(cr['start'] <= r[0] and cr['end'] >= r[1] for cr in checked_ranges):
                    all_checked = False
                    break
            
            if all_checked:
                print(f"\n{Colors.BLUE}COMPLETE: Entire range has been checked.{Colors.END}")
                print(f"{Colors.YELLOW}The target key was not found in the specified range.{Colors.END}")
                break
                
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Interrupted by user{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.RED}Error: {e}{Colors.END}")
    finally:
        save_checked_ranges(checked_ranges)
        show_progress(checked_ranges, start_time)

if __name__ == "__main__":
    import sys
    multiprocessing.freeze_support()
    target_addr = sys.argv[1] if len(sys.argv) > 1 else None
    main(target_addr)
