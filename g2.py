import os
import hashlib
import multiprocessing
import coincurve
from typing import Optional
import time

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

def print_status(checked, total, speed, elapsed):
    """Красивый вывод статуса"""
    progress = (checked / total) * 100
    print(f"\r[STATUS] Checked: {checked:,} | "
          f"Speed: {speed:,.0f} keys/sec | "
          f"Progress: {progress:.4f}% | "
          f"Elapsed: {elapsed:.1f}s", end='', flush=True)

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

def worker(input_queue, output_queue, stats):
    while True:
        try:
            batch = input_queue.get(timeout=1)
            if batch is None:
                break
                
            start, end = batch
            found_key = process_batch(start, end)
            if found_key:
                output_queue.put(found_key)
            
            with stats.get_lock():
                stats.value += end - start + 1
        except:
            break

def save_key(key: str):
    with open(CONFIG['OUTPUT_FILE'], 'a') as f:
        f.write(f"Key: {key}\n")
        f.write(f"Address: {key_to_ripemd160(key).hex()}\n\n")

def key_searcher():
    print(f"[INFO] Starting search from {hex(CONFIG['START_KEY'])} to {hex(CONFIG['END_KEY'])}")
    print(f"[INFO] CPU workers: {CONFIG['WORKERS']}")
    print(f"[INFO] Batch size: {CONFIG['BATCH_SIZE']:,}")
    print(f"[INFO] Target hash: {CONFIG['TARGET_RIPEMD'].hex()}")
    
    total_keys = CONFIG['END_KEY'] - CONFIG['START_KEY']
    print(f"[INFO] Total keys to check: {total_keys:,}")

    input_queue = multiprocessing.Queue(maxsize=CONFIG['WORKERS'] * 2)
    output_queue = multiprocessing.Queue()
    stats = multiprocessing.Value('L', 0)
    last_status = multiprocessing.Value('d', time.time())

    processes = []
    for i in range(CONFIG['WORKERS']):
        p = multiprocessing.Process(
            target=worker,
            args=(input_queue, output_queue, stats),
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

    start_time = time.time()
    last_print = time.time()
    
    while any(p.is_alive() for p in processes):
        time.sleep(0.1)
        
        if not output_queue.empty():
            found_key = output_queue.get()
            print(f"\n[SUCCESS] Found matching key: {found_key}")
            save_key(found_key)

        now = time.time()
        if now - last_print >= CONFIG['STATUS_INTERVAL']:
            with stats.get_lock():
                checked = stats.value
                elapsed = now - start_time
                speed = checked / max(elapsed, 1)
                print_status(checked, total_keys, speed, elapsed)
                last_print = now

    print("\n[INFO] Search completed")
    print(f"[STATS] Total checked: {stats.value:,}")
    print(f"[STATS] Total time: {time.time() - start_time:.1f}s")

if __name__ == "__main__":
    multiprocessing.freeze_support()
    key_searcher()
