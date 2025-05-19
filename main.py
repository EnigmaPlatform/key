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

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    END = '\033[0m'

# Параметры для CPU
CHECKPOINT_FILE = "checked_ranges.json"
FOUND_KEYS_FILE = "found_keys.txt"
CHUNK_SIZE = 10_000_000
MAIN_START = 0x41D6A7E9C0B1D9A9BF
MAIN_END = 0x45FFFFFFFFFFFFFFFFF
BATCH_SIZE = 1_000_000
MAX_WORKERS = multiprocessing.cpu_count() * 2
SAVE_INTERVAL = 5

stop_flag = False
current_chunk = None

def load_checked_ranges():
    if os.path.exists(CHECKPOINT_FILE):
        try:
            with open(CHECKPOINT_FILE, 'r') as f:
                return json.load(f)
        except:
            return []
    return []

def save_checked_ranges(ranges):
    with open(CHECKPOINT_FILE, 'w') as f:
        json.dump(ranges, f, indent=2)

def is_key_checked(key_int, checked_ranges):
    for r in checked_ranges:
        if r['start'] <= key_int <= r['end']:
            return True
    return False

def merge_ranges(ranges):
    if not ranges:
        return []
    
    sorted_ranges = sorted(ranges, key=lambda x: x['start'])
    merged = [sorted_ranges[0]]
    
    for current in sorted_ranges[1:]:
        last = merged[-1]
        if current['start'] <= last['end']:
            last['end'] = max(last['end'], current['end'])
        else:
            merged.append(current)
    
    return merged

def private_to_address(private_key_hex):
    try:
        private_key = bytes.fromhex(private_key_hex)
        public_key = coincurve.PublicKey.from_valid_secret(private_key).format(compressed=True)
        
        sha256 = hashlib.sha256(public_key).digest()
        ripemd160 = hashlib.new('ripemd160', sha256).digest()
        
        extended = b'\x00' + ripemd160
        checksum = hashlib.sha256(hashlib.sha256(extended).digest()).digest()[:4]
        return base58.b58encode(extended + checksum).decode('utf-8')
    except:
        return None

def generate_address_batch(batch):
    return [private_to_address(pk) for pk in batch]

def check_sequential_chunk(start_key, target_address, checked_ranges):
    global stop_flag, current_chunk
    
    end_key = min(start_key + CHUNK_SIZE - 1, MAIN_END)
    current_chunk = {'start': start_key, 'end': end_key}
    found_key = None
    
    with tqdm(total=end_key-start_key+1, 
             desc=f"Проверка {hex(start_key)}-{hex(end_key)}", 
             mininterval=2,
             bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{rate_fmt}{postfix}, {remaining}]",
             dynamic_ncols=True) as pbar:
        
        for batch_start in range(start_key, end_key+1, BATCH_SIZE):
            if stop_flag:
                break
                
            batch_end = min(batch_start + BATCH_SIZE - 1, end_key)
            batch = [format(k, '064x') for k in range(batch_start, batch_end+1)]
            
            with ProcessPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = [executor.submit(generate_address_batch, batch)]
                
                for future in as_completed(futures):
                    results = future.result()
                    if target_address in results:
                        found_key = batch[results.index(target_address)]
                        stop_flag = True
                        break
                        
                    pbar.update(len(results))
            
            if found_key:
                break
    
    if not stop_flag and not found_key:
        checked_ranges.append({
            'start': start_key,
            'end': end_key,
            'checked_at': time.strftime('%Y-%m-%d %H:%M:%S')
        })
        if len(checked_ranges) % SAVE_INTERVAL == 0:
            save_checked_ranges(merge_ranges(checked_ranges))
    
    return found_key

def signal_handler(sig, frame):
    global stop_flag
    print(f"\n{Colors.YELLOW}Получен сигнал прерывания...{Colors.END}")
    stop_flag = True

def main(target_address="1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"):
    global stop_flag
    
    signal.signal(signal.SIGINT, signal_handler)
    
    checked_ranges = merge_ranges(load_checked_ranges())
    total_checked = sum(r['end']-r['start']+1 for r in checked_ranges)
    
    print(f"{Colors.YELLOW}Поиск ключа для адреса: {target_address}{Colors.END}")
    print(f"Уже проверено: {total_checked:,} ключей")
    print(f"Размер блока: {CHUNK_SIZE:,} ключей")
    print(f"Процессов: {MAX_WORKERS}, Пакет: {BATCH_SIZE} ключей\n")

    try:
        next_start = checked_ranges[-1]['end'] + 1 if checked_ranges else MAIN_START
        while not stop_flag and next_start <= MAIN_END:
            if found_key := check_sequential_chunk(next_start, target_address, checked_ranges):
                print(f"\n{Colors.GREEN}Ключ найден!{Colors.END}")
                print(f"Приватный ключ: {found_key}")
                with open(FOUND_KEYS_FILE, "a") as f:
                    f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Private: {found_key}\n")
                    f.write(f"Address: {target_address}\n\n")
                break
                
            next_start = checked_ranges[-1]['end'] + 1
            if next_start > MAIN_END:
                break
                
    except Exception as e:
        print(f"\n{Colors.RED}Ошибка: {e}{Colors.END}")
    finally:
        save_checked_ranges(merge_ranges(checked_ranges))
        total_checked = sum(r['end']-r['start']+1 for r in checked_ranges)
        
        print(f"\n{Colors.YELLOW}Итоги:{Colors.END}")
        print(f"Всего проверено: {total_checked:,} ключей")
        print(f"Осталось проверить: {MAIN_END - MAIN_START + 1 - total_checked:,} ключей")

if __name__ == "__main__":
    import sys
    main(sys.argv[1] if len(sys.argv) > 1 else "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU")
