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
from typing import List, Dict, Optional
from functools import lru_cache

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    END = '\033[0m'

# Конфигурация
CHECKPOINT_FILE = "checked_ranges.json"
FOUND_KEYS_FILE = "found_keys.txt"
CHUNK_SIZE = 10_000_000
MIN_CHUNK_SIZE = 1
MAIN_START = 0x1938ec6e3f2a70000
MAIN_END = 0x1aedf7475bb6d0000
BATCH_SIZE = 5_000_000  # Уменьшенный размер батча для лучшего распределения
MAX_WORKERS = 12
SAVE_INTERVAL = 5
STATUS_INTERVAL = 5

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
    total_checked = sum(r['end']-r['start']+1 for r in ranges)
    remaining = (MAIN_END - MAIN_START + 1) - total_checked
    
    if remaining <= 0:
        return None
    
    # Если осталось меньше 2% от общего диапазона, проверяем все оставшееся
    if remaining < (MAIN_END - MAIN_START + 1) * 0.02:
        return MAIN_START + total_checked, MAIN_END
    
    # Адаптивный размер чанка
    adaptive_chunk_size = min(CHUNK_SIZE, max(MIN_CHUNK_SIZE, remaining // 100))
    
    # Находим первый непроверенный диапазон
    last_end = MAIN_START - 1
    for r in sorted(ranges, key=lambda x: x['start']):
        if r['start'] > last_end + 1:
            unverified_start = last_end + 1
            unverified_end = r['start'] - 1
            chunk_size = min(adaptive_chunk_size, unverified_end - unverified_start + 1)
            start = random.randint(unverified_start, unverified_end - chunk_size + 1)
            return start, start + chunk_size - 1
        last_end = max(last_end, r['end'])
    
    if last_end < MAIN_END:
        unverified_start = last_end + 1
        chunk_size = min(adaptive_chunk_size, MAIN_END - unverified_start + 1)
        return unverified_start, unverified_start + chunk_size - 1
    
    return None

@lru_cache(maxsize=100000)
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

def process_batch(batch_start: int, batch_end: int, target: str) -> Optional[str]:
    for k in range(batch_start, batch_end + 1):
        private_key_hex = f"{k:064x}"
        address = private_to_address(private_key_hex)
        if address == target:
            return private_key_hex
    return None

def check_random_chunk(target: str, ranges: List[Dict]) -> Optional[str]:
    chunk = get_random_chunk(ranges)
    if not chunk:
        return None
        
    start, end = chunk
    chunk_size = end - start + 1
    print(f"\n{Colors.YELLOW}Current range: {hex(start)} - {hex(end)} ({chunk_size:,} keys){Colors.END}")
    
    found_key = None
    try:
        with ProcessPoolExecutor(max_workers=MAX_WORKERS, initializer=init_worker) as executor:
            futures = []
            batch_size = max(BATCH_SIZE, (end - start + 1) // (MAX_WORKERS * 4))
            for batch_start in range(start, end + 1, batch_size):
                batch_end = min(batch_start + batch_size - 1, end)
                futures.append(executor.submit(process_batch, batch_start, batch_end, target))
            
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
        if len(ranges) % SAVE_INTERVAL == 0:
            save_checked_ranges(ranges)
    
    return found_key

def format_large_number(n: int) -> str:
    if n < 1e6:
        return f"{n:,}"
    elif n < 1e9:
        return f"{n/1e6:,.2f}M"
    elif n < 1e12:
        return f"{n/1e9:,.2f}B"
    else:
        return f"{n/1e12:,.2f}T"

def show_status(checked: List[Dict]):
    if not checked:
        print(f"{Colors.YELLOW}No ranges checked yet{Colors.END}")
        return
    
    total_checked = sum(r['end']-r['start']+1 for r in checked)
    total_range = MAIN_END - MAIN_START + 1
    percent = (total_checked / total_range) * 100 if total_range > 0 else 0
    
    print(f"\n{Colors.YELLOW}=== Status ===")
    print(f"Checked: {format_large_number(total_checked)} keys")
    print(f"Progress: {percent:.12f}%")
    print(f"Remaining: {format_large_number(max(0, total_range - total_checked))} keys")
    print(f"Last range: {hex(checked[-1]['start'])} - {hex(checked[-1]['end'])}")
    print(f"=================={Colors.END}")

def main(target_address="1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"):
    checked_ranges = load_checked_ranges()
    last_status_time = time.time()
    total_range = MAIN_END - MAIN_START + 1
    
    print(f"{Colors.YELLOW}Target address: {target_address}{Colors.END}")
    print(f"Search range: {hex(MAIN_START)} - {hex(MAIN_END)}")
    print(f"Total keys: {format_large_number(total_range)}")
    print(f"Chunk size: {format_large_number(CHUNK_SIZE)} (auto-adjusted)")
    print(f"Min chunk size: {MIN_CHUNK_SIZE}")
    print(f"Workers: {MAX_WORKERS}\n")
    
    try:
        start_time = time.time()
        while True:
            current_time = time.time()
            if current_time - last_status_time > STATUS_INTERVAL:
                total_checked = sum(r['end']-r['start']+1 for r in checked_ranges)
                elapsed = current_time - start_time
                keys_per_sec = total_checked / elapsed if elapsed > 0 else 0
                
                print(f"\n{Colors.YELLOW}[Progress] Checked: {format_large_number(total_checked)} keys | "
                      f"Speed: {format_large_number(int(keys_per_sec))} keys/sec | "
                      f"Elapsed: {elapsed:.1f}s{Colors.END}")
                show_status(checked_ranges)
                last_status_time = current_time
            
            if found_key := check_random_chunk(target_address, checked_ranges):
                print(f"\n{Colors.GREEN}Key found!{Colors.END}")
                print(f"Private key: {found_key}")
                with open(FOUND_KEYS_FILE, 'a') as f:
                    f.write(f"{time.ctime()}\n")
                    f.write(f"Private: {found_key}\n")
                    f.write(f"Address: {target_address}\n\n")
                break
                
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Interrupted by user{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.RED}Error: {e}{Colors.END}")
    finally:
        save_checked_ranges(checked_ranges)
        show_status(checked_ranges)

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
