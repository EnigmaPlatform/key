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

# Configuration
CHECKPOINT_FILE = "checked_ranges.json"
FOUND_KEYS_FILE = "found_keys.txt"
CHUNK_SIZE = 100_000_000
MIN_CHUNK_SIZE = 1
MAIN_START = 0x1732C9CD0474A0000
MAIN_END = 0x1A12F1DA9D70A0000
BATCH_SIZE = 100_000_000
MAX_WORKERS = min(12, (os.cpu_count() or 1) * 2)
SAVE_INTERVAL = 5
STATUS_INTERVAL = 30

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
    
    # Get all unverified ranges first
    unverified_ranges = []
    last_end = MAIN_START - 1
    
    # Sort checked ranges by start
    sorted_ranges = sorted(ranges, key=lambda x: x['start'])
    
    for r in sorted_ranges:
        if r['start'] > last_end + 1:
            unverified_ranges.append((last_end + 1, r['start'] - 1))
        last_end = max(last_end, r['end'])
    
    if last_end < MAIN_END:
        unverified_ranges.append((last_end + 1, MAIN_END))
    
    # Select a random unverified range
    if not unverified_ranges:
        return None
    
    selected_range = random.choice(unverified_ranges)
    range_start, range_end = selected_range
    range_size = range_end - range_start + 1
    
    # If the range is small, return the whole thing
    if range_size <= CHUNK_SIZE * 2:  # Use *2 to prevent too small chunks
        return range_start, range_end
    
    # Otherwise select a random chunk within this range
    chunk_size = min(CHUNK_SIZE, range_size)
    start = random.randint(range_start, range_end - chunk_size + 1)
    end = start + chunk_size - 1
    
    return start, end

def private_to_address(private_key_hex: str) -> Optional[str]:
    try:
        priv = bytes.fromhex(private_key_hex)
        pub = coincurve.PublicKey.from_valid_secret(priv).format(compressed=True)
        h160 = hashlib.new('ripemd160', hashlib.sha256(pub).digest()).digest()
        extended = b'\x00' + h160
        checksum = hashlib.sha256(hashlib.sha256(extended).digest()).digest()[:4]
        return base58.b58encode(extended + checksum).decode('utf-8')
    except:
        return None

def process_batch(batch: List[str], target: str) -> Optional[str]:
    for pk in batch:
        try:
            if private_to_address(pk) == target:
                return pk
        except:
            continue
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
            for batch_start in range(start, end + 1, BATCH_SIZE):
                batch_end = min(batch_start + BATCH_SIZE - 1, end)
                batch = [format(k, '064x') for k in range(batch_start, batch_end + 1)]
                futures.append(executor.submit(process_batch, batch, target))
            
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

def show_status(checked: List[Dict]):
    if not checked:
        print(f"{Colors.YELLOW}No ranges checked yet{Colors.END}")
        return
    
    total_checked = sum(r['end']-r['start']+1 for r in checked)
    total_range = MAIN_END - MAIN_START + 1
    percent = (total_checked / total_range) * 100 if total_range > 0 else 0
    
    print(f"\n{Colors.YELLOW}=== Status ===")
    print(f"Checked: {total_checked:,} keys")
    print(f"Progress: {percent:.6f}%")
    print(f"Remaining: {max(0, total_range - total_checked):,} keys")
    print(f"Last range: {hex(checked[-1]['start'])} - {hex(checked[-1]['end'])}")
    print(f"=================={Colors.END}")

def main(target_address="1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"):
    checked_ranges = load_checked_ranges()
    last_status_time = time.time()
    total_range = MAIN_END - MAIN_START + 1
    
    print(f"{Colors.YELLOW}Target address: {target_address}{Colors.END}")
    print(f"Search range: {hex(MAIN_START)} - {hex(MAIN_END)}")
    print(f"Total keys: {total_range:,}")
    print(f"Chunk size: {CHUNK_SIZE:,} (auto-adjusted)")
    print(f"Min chunk size: {MIN_CHUNK_SIZE:,}")
    print(f"Workers: {MAX_WORKERS}\n")
    
    try:
        start_time = time.time()
        while True:
            current_time = time.time()
            if current_time - last_status_time > STATUS_INTERVAL:
                total_checked = sum(r['end']-r['start']+1 for r in checked_ranges)
                elapsed = current_time - start_time
                keys_per_sec = total_checked / elapsed if elapsed > 0 else 0
                
                print(f"\n{Colors.YELLOW}[Progress] Checked: {total_checked:,} keys | "
                      f"Speed: {keys_per_sec:,.0f} keys/sec | "
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
