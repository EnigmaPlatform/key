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
import math

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    END = '\033[0m'

CONFIG = {
    'CHECKPOINT_FILE': "checked_ranges.json",
    'FOUND_KEYS_FILE': "found_keys.txt",
    'BATCH_SIZE': 10_000_000,  # 10M ключей на блок
    'MAX_WORKERS': multiprocessing.cpu_count() * 2,
    'STATUS_INTERVAL': 5,
    'TARGET_ADDRESS': "19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR",
    'START': 0x349b84b6431a6b4ef1,
    'END': 0x349b84b6431a6c4ef1,
    #'HEX_PATTERN': '1a12f1d',
    'BANNED_SUFFIXES': ['aaaa', 'ffff'],
    'BIT_TRANSITIONS_RANGE': (7, 9)
}

def init_worker():
    signal.signal(signal.SIGINT, signal.SIG_IGN)

def load_checked_ranges() -> List[Dict]:
    if os.path.exists(CONFIG['CHECKPOINT_FILE']):
        try:
            with open(CONFIG['CHECKPOINT_FILE'], 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"{Colors.RED}Ошибка загрузки чекпоинтов: {e}{Colors.END}")
    return []

def save_checked_ranges(ranges: List[Dict]):
    try:
        with open(CONFIG['CHECKPOINT_FILE'], 'w') as f:
            json.dump(ranges, f, indent=2)
    except Exception as e:
        print(f"{Colors.RED}Ошибка сохранения чекпоинтов: {e}{Colors.END}")

def is_range_checked(start: int, end: int, ranges: List[Dict]) -> bool:
    return any(r['start'] <= start and r['end'] >= end for r in ranges)

#def is_valid_key(key: int) -> bool:
    #hex_key = hex(key)[2:]
    #return (
        #CONFIG['HEX_PATTERN'] in hex_key and
       # not any(hex_key.endswith(s) for s in CONFIG['BANNED_SUFFIXES']) and
       # CONFIG['BIT_TRANSITIONS_RANGE'][0] <= bin(key).count('01') <= CONFIG['BIT_TRANSITIONS_RANGE'][1]
   # )

@lru_cache(maxsize=2_000_000)
def private_to_address(private_key_hex: str) -> Optional[str]:
    try:
        priv = bytes.fromhex(private_key_hex)
        pub = coincurve.PublicKey.from_valid_secret(priv).format(compressed=True)
        h160 = hashlib.new('ripemd160', hashlib.sha256(pub).digest()).digest()
        extended = b'\x00' + h160
        checksum = hashlib.sha256(hashlib.sha256(extended).digest()).digest()[:4]
        return base58.b58encode(extended + checksum).decode('utf-8')
    except Exception:
        return None

def generate_chunks() -> List[Tuple[int, int]]:
    """Генерирует чанки по 10M, начиная от центра"""
    center = (CONFIG['START'] + CONFIG['END']) // 2
    chunk_size = CONFIG['BATCH_SIZE']
    radius = CONFIG['END'] - center
    
    chunks = []
    for direction in [1, -1]:  # 1 = вправо, -1 = влево
        for offset in range(0, radius, chunk_size):
            if direction == 1:
                start = center + offset
                end = min(start + chunk_size - 1, CONFIG['END'])
            else:
                end = center - offset - 1
                start = max(end - chunk_size + 1, CONFIG['START'])
            
            chunks.append((start, end))
    
    return chunks

def process_chunk(start: int, end: int) -> Optional[Tuple[int, str]]:
    start_time = time.time()
    last_log_time = time.time()
    
    for key in range(start, end + 1):
        if not is_valid_key(key):
            continue
            
        private_key = f"{key:064x}"
        address = private_to_address(private_key)
        
        if address == CONFIG['TARGET_ADDRESS']:
            return (key, private_key)
        
        # Логирование прогресса каждые 30 секунд
        if time.time() - last_log_time > 30:
            speed = int((key - start) / max(1, time.time() - start_time))
            print(f"{Colors.CYAN}[PID {os.getpid()}] {hex(key)} | Speed: {speed:,} keys/s{Colors.END}")
            last_log_time = time.time()
    
    return None

def main():
    print(f"{Colors.CYAN}\n=== Bitcoin Puzzle 71 Solver ===")
    print(f"Целевой адрес: {CONFIG['TARGET_ADDRESS']}")
    print(f"Диапазон: {hex(CONFIG['START'])} - {hex(CONFIG['END'])}")
    print(f"Всего ключей: {(CONFIG['END']-CONFIG['START']+1):,}")
    print(f"Размер чанка: {CONFIG['BATCH_SIZE']:,}")
    print(f"Процессы: {CONFIG['MAX_WORKERS']}")
    print(f"=============================={Colors.END}")
    
    checked_ranges = load_checked_ranges()
    chunks = generate_chunks()
    total_chunks = len(chunks)
    processed_chunks = 0
    start_time = time.time()
    
    with ProcessPoolExecutor(max_workers=CONFIG['MAX_WORKERS'], initializer=init_worker) as executor:
        futures = {executor.submit(process_chunk, start, end): (start, end) for start, end in chunks}
        
        for future in as_completed(futures):
            start, end = futures[future]
            processed_chunks += 1
            
            # Расчет прогресса
            elapsed = time.time() - start_time
            keys_processed = (end - start + 1) * processed_chunks
            total_keys = (CONFIG['END'] - CONFIG['START'] + 1)
            percent = min(100, (keys_processed / total_keys) * 100)
            speed = int(keys_processed / elapsed) if elapsed > 0 else 0
            
            print(f"\n{Colors.YELLOW}=== Прогресс ===")
            print(f"Чанков: {processed_chunks}/{total_chunks}")
            print(f"Ключей: {keys_processed:,}/{total_keys:,}")
            print(f"Прогресс: {percent:.2f}%")
            print(f"Скорость: {speed:,} keys/s")
            print(f"Время: {time.strftime('%H:%M:%S', time.gmtime(elapsed))}")
            print(f"Текущий: {hex(start)}-{hex(end)}")
            print(f"=================={Colors.END}")
            
            if result := future.result():
                print(f"\n{Colors.GREEN}>>> КЛЮЧ НАЙДЕН! <<<{Colors.END}")
                print(f"Приватный ключ: {result[1]}")
                with open(CONFIG['FOUND_KEYS_FILE'], 'w') as f:
                    f.write(f"Адрес: {CONFIG['TARGET_ADDRESS']}\n")
                    f.write(f"Ключ: {result[1]}\n")
                return
            
            # Сохраняем прогресс
            checked_ranges.append({'start': start, 'end': end, 'time': time.time()})
            if processed_chunks % 10 == 0:
                save_checked_ranges(checked_ranges)
    
    print(f"\n{Colors.BLUE}Поиск завершен. Ключ не найден.{Colors.END}")
    save_checked_ranges(checked_ranges)

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
