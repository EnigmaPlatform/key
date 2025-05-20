import hashlib
import base58
import time
import json
import os
import multiprocessing
import coincurve
from typing import Optional, List
from functools import lru_cache

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'

CONFIG = {
    'CHECKPOINT_FILE': "checkpoint.json",
    'FOUND_KEYS_FILE': "found_keys.txt",
    'SAVE_INTERVAL': 10_000_000,
    'STATUS_INTERVAL': 300,  # 5 минут = 300 секунд
    'TARGET_ADDRESS': "19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR",
    'START_KEY': 0x349b84b643180c4ef1,
    'END_KEY': 0x349b84b6431a6c4ef1,
    'BATCH_PER_CORE': 5_000_000  # Увеличенный размер пакета
}

def load_checkpoint() -> int:
    if not os.path.exists(CONFIG['CHECKPOINT_FILE']):
        return CONFIG['START_KEY']
    
    try:
        with open(CONFIG['CHECKPOINT_FILE'], 'r') as f:
            data = json.load(f)
            return int(data['last_key'], 16) + 1
    except Exception as e:
        print(f"{Colors.RED}Error loading checkpoint: {e}{Colors.END}")
        return CONFIG['START_KEY']

def save_checkpoint(current_key: int):
    try:
        with open(CONFIG['CHECKPOINT_FILE'], 'w') as f:
            json.dump({'last_key': hex(current_key)}, f)
    except Exception as e:
        print(f"{Colors.RED}Error saving checkpoint: {e}{Colors.END}")

@lru_cache(maxsize=2_000_000)
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

def process_keys(key_range: range, target: str, result_queue: multiprocessing.Queue):
    for k in key_range:
        private_key = f"{k:064x}"
        if private_to_address(private_key) == target:
            result_queue.put(private_key)
            return
    result_queue.put(None)

def format_speed(speed: float) -> str:
    if speed >= 1_000_000:
        return f"{speed/1_000_000:.2f} M keys/sec"
    return f"{speed:,.0f} keys/sec"

def main():
    print(f"{Colors.YELLOW}Target address: {CONFIG['TARGET_ADDRESS']}{Colors.END}")
    print(f"Search range: {hex(CONFIG['START_KEY'])} - {hex(CONFIG['END_KEY'])}")
    
    current_key = load_checkpoint()
    if current_key > CONFIG['START_KEY']:
        print(f"{Colors.BLUE}Resuming from checkpoint: {hex(current_key)}{Colors.END}")
    
    num_cores = multiprocessing.cpu_count()
    print(f"{Colors.BLUE}Using {num_cores} CPU cores{Colors.END}")
    print(f"{Colors.YELLOW}Status updates every 5 minutes{Colors.END}\n")
    
    manager = multiprocessing.Manager()
    result_queue = manager.Queue()
    processes = []
    last_status_time = time.time()
    start_time = time.time()
    total_checked = 0
    batch_size = CONFIG['BATCH_PER_CORE'] * num_cores
    found_key = None

    try:
        while current_key <= CONFIG['END_KEY'] and not found_key:
            batch_end = min(current_key + batch_size - 1, CONFIG['END_KEY'])
            
            # Разделяем работу между ядрами
            ranges = []
            keys_per_core = (batch_end - current_key + 1) // num_cores
            for i in range(num_cores):
                start = current_key + i * keys_per_core
                end = start + keys_per_core - 1 if i < num_cores - 1 else batch_end
                ranges.append(range(start, end + 1))
            
            # Запускаем процессы
            processes = []
            for r in ranges:
                p = multiprocessing.Process(
                    target=process_keys,
                    args=(r, CONFIG['TARGET_ADDRESS'], result_queue)
                )
                p.start()
                processes.append(p)
            
            # Ожидаем завершения и проверяем результаты
            for _ in range(num_cores):
                if key := result_queue.get():
                    found_key = key
                    break
            
            # Останавливаем все процессы если ключ найден
            if found_key:
                for p in processes:
                    p.terminate()
                break
            
            # Обновляем статус
            total_checked += batch_end - current_key + 1
            current_key = batch_end + 1
            
            if time.time() - last_status_time >= CONFIG['STATUS_INTERVAL']:
                elapsed = time.time() - start_time
                keys_per_sec = total_checked / elapsed
                print(
                    f"{Colors.YELLOW}[Status] Keys: {total_checked:,} | "
                    f"Speed: {format_speed(keys_per_sec)} | "
                    f"Current: {hex(current_key)} | "
                    f"Elapsed: {elapsed/60:.1f} min{Colors.END}"
                )
                last_status_time = time.time()
            
            # Сохраняем прогресс
            if current_key % CONFIG['SAVE_INTERVAL'] == 0:
                save_checkpoint(current_key)
        
        # Финализация
        if found_key:
            print(f"\n{Colors.GREEN}SUCCESS: Key found!{Colors.END}")
            print(f"Private key: {found_key}")
            with open(CONFIG['FOUND_KEYS_FILE'], 'a') as f:
                f.write(f"{time.ctime()}\n")
                f.write(f"Private: {found_key}\n")
                f.write(f"Address: {CONFIG['TARGET_ADDRESS']}\n\n")
        else:
            print(f"\n{Colors.BLUE}COMPLETE: Entire range has been checked.{Colors.END}")
            print(f"{Colors.YELLOW}The target key was not found in the specified range.{Colors.END}")
            
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Interrupted by user{Colors.END}")
        save_checkpoint(current_key)
    except Exception as e:
        print(f"\n{Colors.RED}Error: {e}{Colors.END}")
    finally:
        for p in processes:
            p.terminate()
        
        elapsed = time.time() - start_time
        keys_per_sec = total_checked / elapsed if elapsed > 0 else 0
        print(f"\n{Colors.BLUE}=== FINAL STATS ===")
        print(f"Total keys checked: {total_checked:,}")
        print(f"Total time: {elapsed/60:.1f} minutes")
        print(f"Average speed: {format_speed(keys_per_sec)}")
        print(f"Last checked key: {hex(current_key)}")
        print(f"=================={Colors.END}")

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
