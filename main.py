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

# Конфигурация с безопасными границами
CONFIG = {
    'CHECKPOINT_FILE': "checked_ranges.json",
    'FOUND_KEYS_FILE': "found_keys.txt",
    'CHUNK_SIZE': 10_000_000,
    'MIN_CHUNK_SIZE': 1_000,
    'MAIN_START': 0x349b84b6431a4c4ef1,
    'MAIN_END': 0x349b84b6431a6c4ef1,
    'BATCH_SIZE': 100_000,
    'MAX_WORKERS': multiprocessing.cpu_count(),
    'SAVE_INTERVAL': 5,
    'STATUS_INTERVAL': 60,
    'TARGET_ADDRESS': "19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR"
}

def init_worker():
    signal.signal(signal.SIGINT, signal.SIG_IGN)

def load_checked_ranges() -> List[Dict]:
    if not os.path.exists(CONFIG['CHECKPOINT_FILE']):
        return []
    
    try:
        with open(CONFIG['CHECKPOINT_FILE'], 'r') as f:
            data = json.load(f)
            if not isinstance(data, list):
                return []
            return [r for r in data if isinstance(r, dict) and 
                   'start' in r and 'end' in r and r['start'] <= r['end']]
    except Exception as e:
        print(f"{Colors.RED}Error loading checkpoint file: {e}{Colors.END}")
        return []

def save_checked_ranges(ranges: List[Dict]):
    try:
        with open(CONFIG['CHECKPOINT_FILE'], 'w') as f:
            json.dump(ranges, f, indent=2)
    except Exception as e:
        print(f"{Colors.RED}Error saving checkpoint file: {e}{Colors.END}")

def is_range_checked(start: int, end: int, ranges: List[Dict]) -> bool:
    return any(r['start'] <= start <= r['end'] or r['start'] <= end <= r['end'] for r in ranges)

def get_unverified_ranges(ranges: List[Dict]) -> List[Tuple[int, int]]:
    sorted_ranges = sorted(ranges, key=lambda x: x['start'])
    unverified = []
    last_end = CONFIG['MAIN_START'] - 1
    
    for r in sorted_ranges:
        current_start = max(r['start'], CONFIG['MAIN_START'])
        current_end = min(r['end'], CONFIG['MAIN_END'])
        
        if current_start > last_end + 1:
            unverified_start = last_end + 1
            unverified_end = current_start - 1
            if unverified_start <= unverified_end:
                unverified.append((unverified_start, unverified_end))
        last_end = max(last_end, current_end)
    
    if last_end < CONFIG['MAIN_END']:
        unverified.append((last_end + 1, CONFIG['MAIN_END']))
    
    return unverified

def get_random_chunk(ranges: List[Dict]) -> Optional[Tuple[int, int]]:
    unverified = get_unverified_ranges(ranges)
    if not unverified:
        return None
    
    valid_ranges = []
    for start, end in unverified:
        if (start >= CONFIG['MAIN_START'] and 
            end <= CONFIG['MAIN_END'] and 
            start <= end and 
            end - start + 1 >= CONFIG['MIN_CHUNK_SIZE']):
            valid_ranges.append((start, end))
    
    if not valid_ranges:
        return None
    
    range_start, range_end = random.choice(valid_ranges)
    range_size = range_end - range_start + 1
    
    chunk_size = min(
        CONFIG['CHUNK_SIZE'],
        max(CONFIG['MIN_CHUNK_SIZE'], range_size // 10),
        range_size
    )
    
    max_possible_start = range_end - chunk_size + 1
    start = random.randint(range_start, max_possible_start)
    end = start + chunk_size - 1
    
    return max(start, CONFIG['MAIN_START']), min(end, CONFIG['MAIN_END'])

@lru_cache(maxsize=1_000_000)
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

def process_batch(batch: List[str], target: str) -> Optional[str]:
    for pk in batch:
        address = private_to_address(pk)
        if address == target:
            return pk
    return None

def generate_batches(start: int, end: int) -> List[List[str]]:
    batch_size = CONFIG['BATCH_SIZE']
    batches = []
    current = max(start, CONFIG['MAIN_START'])
    end = min(end, CONFIG['MAIN_END'])
    
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
    for unit in ['', 'K', 'M', 'B', 'T', 'P']:
        if abs(n) < 1000:
            return f"{n:,.0f}{unit}"
        n /= 1000
    return f"{n:,.0f}?"

def show_status(checked: List[Dict]):
    if not checked:
        print(f"{Colors.YELLOW}No ranges checked yet{Colors.END}")
        return
    
    try:
        total_checked = sum(max(0, r['end']-r['start']+1) for r in checked)
        total_range = max(1, CONFIG['MAIN_END'] - CONFIG['MAIN_START'] + 1)
        percent = min(100, (total_checked / total_range) * 100)
        
        print(f"\n{Colors.YELLOW}=== Status ===")
        print(f"Checked: {format_large_number(total_checked)} keys")
        print(f"Progress: {percent:.8f}%")
        print(f"Remaining: {format_large_number(max(0, total_range - total_checked))} keys")
        if checked:
            print(f"Last range: {hex(checked[-1]['start'])} - {hex(checked[-1]['end'])}")
        print(f"=================={Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}Error calculating stats: {e}{Colors.END}")

def show_final_stats(checked: List[Dict], start_time: float):
    total_checked = sum(max(0, r['end']-r['start']+1) for r in checked) if checked else 0
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
    start_time = time.time()
    
    target = target_address if target_address else CONFIG['TARGET_ADDRESS']
    print(f"{Colors.YELLOW}Target address: {target}{Colors.END}")
    print(f"Search range: {hex(CONFIG['MAIN_START'])} - {hex(CONFIG['MAIN_END'])}")
    print(f"Total keys: {format_large_number(CONFIG['MAIN_END'] - CONFIG['MAIN_START'] + 1)}")
    print(f"Chunk size: {format_large_number(CONFIG['CHUNK_SIZE'])} (auto-adjusted)")
    print(f"Min chunk size: {CONFIG['MIN_CHUNK_SIZE']}")
    print(f"Workers: {CONFIG['MAX_WORKERS']}\n")
    
    try:
        found_key = None
        while True:
            current_time = time.time()
            if current_time - last_status_time > CONFIG['STATUS_INTERVAL']:
                total_checked = sum(max(0, r['end']-r['start']+1) for r in checked_ranges)
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
