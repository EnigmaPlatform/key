import hashlib
import base58
import time
import json
import os
import multiprocessing
import coincurve
from typing import Optional
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
    'STATUS_INTERVAL': 10,        # Обновлять статус каждые 10 секунд
    'BATCH_SIZE': 100_000,        # Размер пакета для обработки
    'TARGET_ADDRESS': "19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR",
    'START_KEY': 0x349b84b6431a4c4ef1,
    'END_KEY': 0x349b84b6431a6c4ef1
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

def process_range(start_key: int, end_key: int, target: str) -> Optional[str]:
    current_key = start_key
    last_save_key = start_key
    last_status_time = time.time()
    keys_processed = 0
    start_time = time.time()
    
    while current_key <= end_key:
        batch = []
        batch_end = min(current_key + CONFIG['BATCH_SIZE'] - 1, end_key)
        
        # Генерируем пакет ключей
        for k in range(current_key, batch_end + 1):
            private_key = f"{k:064x}"
            address = private_to_address(private_key)
            
            if address == target:
                return private_key
            
            keys_processed += 1
            
            # Сохранение прогресса
            if k - last_save_key >= CONFIG['SAVE_INTERVAL']:
                save_checkpoint(k)
                last_save_key = k
            
            # Вывод статуса
            if time.time() - last_status_time >= CONFIG['STATUS_INTERVAL']:
                elapsed = time.time() - start_time
                keys_per_sec = keys_processed / elapsed if elapsed > 0 else 0
                print(f"{Colors.YELLOW}[Status] Keys: {keys_processed:,} | Speed: {keys_per_sec:,.0f} keys/sec | Current: {hex(k)}{Colors.END}")
                last_status_time = time.time()
                keys_processed = 0
                start_time = time.time()
        
        current_key = batch_end + 1
    
    save_checkpoint(end_key)
    return None

def main():
    print(f"{Colors.YELLOW}Target address: {CONFIG['TARGET_ADDRESS']}{Colors.END}")
    print(f"Search range: {hex(CONFIG['START_KEY'])} - {hex(CONFIG['END_KEY'])}")
    
    start_key = load_checkpoint()
    if start_key > CONFIG['START_KEY']:
        print(f"{Colors.BLUE}Resuming from checkpoint: {hex(start_key)}{Colors.END}")
    
    try:
        found_key = process_range(start_key, CONFIG['END_KEY'], CONFIG['TARGET_ADDRESS'])
        
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
    except Exception as e:
        print(f"\n{Colors.RED}Error: {e}{Colors.END}")

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
