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
    'SAVE_INTERVAL': 10_000_000,  # Сохранять каждый 10 миллионов ключей
    'STATUS_INTERVAL': 30,         # Обновлять статус каждые 30 секунд
    'TARGET_ADDRESS': "19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR",
    'START_KEY': 0x349b84b643180c4ef1,
    'END_KEY': 0x349b84b6431a6c4ef1,
    'BATCH_PER_CORE': 1_000_000    # Количество ключей на ядро за одну итерацию
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

def process_keys(key_range: range, target: str) -> Optional[str]:
    for k in key_range:
        private_key = f"{k:064x}"
        if private_to_address(private_key) == target:
            return private_key
    return None

def main():
    print(f"{Colors.YELLOW}Target address: {CONFIG['TARGET_ADDRESS']}{Colors.END}")
    print(f"Search range: {hex(CONFIG['START_KEY'])} - {hex(CONFIG['END_KEY'])}")
    
    current_key = load_checkpoint()
    if current_key > CONFIG['START_KEY']:
        print(f"{Colors.BLUE}Resuming from checkpoint: {hex(current_key)}{Colors.END}")
    
    num_cores = multiprocessing.cpu_count()
    print(f"{Colors.BLUE}Using {num_cores} CPU cores{Colors.END}")
    
    manager = multiprocessing.Manager()
    found_key = manager.Value('c', '')
    last_status_time = time.time()
    start_time = time.time()
    total_checked = 0
    batch_size = CONFIG['BATCH_PER_CORE'] * num_cores
    
    try:
        with multiprocessing.Pool(processes=num_cores) as pool:
            while current_key <= CONFIG['END_KEY'] and not found_key.value:
                batch_end = min(current_key + batch_size - 1, CONFIG['END_KEY'])
                
                # Разделяем работу между ядрами
                ranges = []
                keys_per_core = (batch_end - current_key + 1) // num_cores
                for i in range(num_cores):
                    start = current_key + i * keys_per_core
                    end = start + keys_per_core - 1 if i < num_cores - 1 else batch_end
                    ranges.append(range(start, end + 1))
                
                # Параллельная обработка
                results = [pool.apply_async(process_keys, (r, CONFIG['TARGET_ADDRESS'])) for r in ranges]
                
                # Проверяем результаты
                for res in results:
                    if key := res.get():
                        found_key.value = key
                        break
                
                # Обновляем статус
                total_checked += batch_end - current_key + 1
                current_key = batch_end + 1
                
                if time.time() - last_status_time >= CONFIG['STATUS_INTERVAL']:
                    elapsed = time.time() - start_time
                    keys_per_sec = total_checked / elapsed if elapsed > 0 else 0
                    print(f"{Colors.YELLOW}[Status] Keys: {total_checked:,} | Speed: {keys_per_sec:,.0f} keys/sec | Current: {hex(current_key)}{Colors.END}")
                    last_status_time = time.time()
                
                # Сохраняем прогресс
                if current_key % CONFIG['SAVE_INTERVAL'] == 0:
                    save_checkpoint(current_key)
            
            # Финализация
            if found_key.value:
                print(f"\n{Colors.GREEN}SUCCESS: Key found!{Colors.END}")
                print(f"Private key: {found_key.value}")
                with open(CONFIG['FOUND_KEYS_FILE'], 'a') as f:
                    f.write(f"{time.ctime()}\n")
                    f.write(f"Private: {found_key.value}\n")
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
        elapsed = time.time() - start_time
        keys_per_sec = total_checked / elapsed if elapsed > 0 else 0
        print(f"\n{Colors.BLUE}=== FINAL STATS ===")
        print(f"Total keys checked: {total_checked:,}")
        print(f"Total time: {elapsed:.2f} seconds")
        print(f"Average speed: {keys_per_sec:,.0f} keys/sec")
        print(f"Last checked key: {hex(current_key)}")
        print(f"=================={Colors.END}")

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
