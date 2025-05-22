import os
import hashlib
import multiprocessing
import coincurve
from typing import Optional
import time
from datetime import datetime, timedelta

# Конфигурация
CONFIG = {
    'TARGET_RIPEMD': bytes.fromhex("5db8cda53a6a002db10365967d7f85d19e171b10"),
    'START_KEY': 0x349b84b6401a6c4ef1,
    'END_KEY': 0x349b84b6431a6c4ef1,
    'OUTPUT_FILE': 'found_keys.txt',
    'BATCH_SIZE': 1_000_000,
    'WORKERS': multiprocessing.cpu_count(),
    'MAX_DUPLICATES': 2,
    'MIN_MIXED_CHARS': 4,
    'STATUS_INTERVAL': 5
}

class StatusMonitor:
    def __init__(self, total_keys):
        self.total_keys = total_keys
        self.start_time = time.time()
        self.last_print = 0
        self.checked = multiprocessing.Value('L', 0)
        self.lock = multiprocessing.Lock()
        
    def update(self, count):
        with self.lock:
            self.checked.value += count
            
    def print_status(self):
        with self.lock:
            now = time.time()
            if now - self.last_print >= CONFIG['STATUS_INTERVAL']:
                elapsed = now - self.start_time
                keys_per_sec = self.checked.value / max(elapsed, 1)
                progress = (self.checked.value / self.total_keys) * 100
                remaining = (self.total_keys - self.checked.value) / max(keys_per_sec, 1)
                
                print(f"\r[STATUS] Checked: {self.checked.value:,} | "
                      f"Speed: {keys_per_sec:,.0f} keys/sec | "
                      f"Progress: {progress:.4f}% | "
                      f"Elapsed: {str(timedelta(seconds=int(elapsed))} | "
                      f"Remaining: {str(timedelta(seconds=int(remaining))}",
                      end='', flush=True)
                self.last_print = now

def is_valid_key(key_hex: str) -> bool:
    if ('000' in key_hex or '111' in key_hex or '222' in key_hex or '333' in key_hex or
        'aaa' in key_hex or 'bbb' in key_hex or 'ccc' in key_hex or 'ddd' in key_hex):
        return False
    
    digits = sum(c.isdigit() for c in key_hex[-16:])
    letters = 16 - digits
    return digits >= 4 and letters >= 4

def key_to_ripemd160(key_hex: str) -> Optional[bytes]:
    try:
        priv = bytes.fromhex(key_hex)
        pub_key = coincurve.PublicKey.from_secret(priv).format(compressed=True)
        return hashlib.new('ripemd160', hashlib.sha256(pub_key).digest())
    except Exception:
        return None

def process_batch(start: int, end: int) -> Optional[str]:
    for k in range(start, end + 1):
        key = f"{k:064x}"
        if not is_valid_key(key):
            continue
            
        ripemd = key_to_ripemd160(key)
        if ripemd and ripemd == CONFIG['TARGET_RIPEMD']:
            return key
    return None

def worker(input_queue, output_queue, status_monitor):
    while True:
        try:
            batch = input_queue.get(timeout=1)
            if batch is None:
                break
                
            start, end = batch
            found_key = process_batch(start, end)
            if found_key:
                output_queue.put(found_key)
            
            status_monitor.update(end - start + 1)
            status_monitor.print_status()
        except:
            break

def save_key(key: str):
    with open(CONFIG['OUTPUT_FILE'], 'a') as f:
        f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Key: {key}\n")
        f.write(f"Address: {key_to_ripemd160(key).hex()}\n\n")

def key_searcher():
    print(f"[INFO] Starting search at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[INFO] Range: {hex(CONFIG['START_KEY'])} to {hex(CONFIG['END_KEY'])}")
    print(f"[INFO] CPU workers: {CONFIG['WORKERS']}")
    print(f"[INFO] Batch size: {CONFIG['BATCH_SIZE']:,}")
    print(f"[INFO] Target hash: {CONFIG['TARGET_RIPEMD'].hex()}")
    
    total_keys = CONFIG['END_KEY'] - CONFIG['START_KEY']
    print(f"[INFO] Total keys to check: {total_keys:,}")

    input_queue = multiprocessing.Queue(maxsize=CONFIG['WORKERS'] * 2)
    output_queue = multiprocessing.Queue()
    status_monitor = StatusMonitor(total_keys)

    processes = []
    for i in range(CONFIG['WORKERS']):
        p = multiprocessing.Process(
            target=worker,
            args=(input_queue, output_queue, status_monitor),
            daemon=True
        )
        p.start()
        processes.append(p)
        print(f"[WORKER] Started worker {i+1}/{CONFIG['WORKERS']}")

    current = CONFIG['START_KEY']
    while current <= CONFIG['END_KEY']:
        batch_end = min(current + CONFIG['BATCH_SIZE'] - 1, CONFIG['END_KEY'])
        input_queue.put((current, batch_end))
        current = batch_end + 1

    for _ in range(CONFIG['WORKERS']):
        input_queue.put(None)

    found_keys = 0
    while any(p.is_alive() for p in processes):
        time.sleep(0.1)
        
        while not output_queue.empty():
            found_key = output_queue.get()
            found_keys += 1
            print(f"\n[SUCCESS] Found matching key: {found_key}")
            save_key(found_key)
        
        status_monitor.print_status()

    print("\n[INFO] Search completed")
    print(f"[STATS] Total checked: {status_monitor.checked.value:,}")
    print(f"[STATS] Total found: {found_keys}")
    print(f"[STATS] Total time: {str(timedelta(seconds=int(time.time() - status_monitor.start_time))}")

if __name__ == "__main__":
    multiprocessing.freeze_support()
    key_searcher()
