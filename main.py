
import hashlib
import random
import base58
import ecdsa
import time
import json
import os
from tqdm import tqdm

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    END = '\033[0m'

# Конфигурация
CHECKPOINT_FILE = "checked_ranges.json"
FOUND_KEYS_FILE = "found_keys.txt"
CHUNK_SIZE = 10_000_000
MAIN_START = 0x6937096C8633D89DE2
MAIN_END = 0x6937096C8634D89DE2

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

def generate_address(private_key_hex):
    try:
        private_key_bytes = bytes.fromhex(private_key_hex)
        sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        
        x = vk.pubkey.point.x()
        y = vk.pubkey.point.y()
        prefix = '02' if y % 2 == 0 else '03'
        public_key_compressed = bytes.fromhex(prefix + "%064x" % x)
        
        sha256 = hashlib.sha256(public_key_compressed).digest()
        ripemd160 = hashlib.new('ripemd160', sha256).digest()
        
        extended_hash = b'\x00' + ripemd160
        checksum = hashlib.sha256(hashlib.sha256(extended_hash).digest()).digest()[:4]
        return base58.b58encode(extended_hash + checksum).decode('utf-8')
    except:
        return None

def log_success(private_key_hex, address):
    print(f"\n{Colors.GREEN}Найден ключ!{Colors.END}")
    print(f"Приватный: {private_key_hex}")
    print(f"Адрес: {address}\n")
    
    with open(FOUND_KEYS_FILE, "a") as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Private: {private_key_hex}\n")
        f.write(f"Address: {address}\n\n")

def check_sequential_chunk(start_key, target_address, checked_ranges):
    end_key = min(start_key + CHUNK_SIZE - 1, MAIN_END)
    found_key = None
    
    # Настройка прогресс-бара с обновлением каждые 1000 ключей
    with tqdm(total=end_key-start_key+1, 
             desc=f"Диапазон {hex(start_key)[2:10]}...", 
             mininterval=2,  # Минимальный интервал обновления (секунды)
             bar_format="{desc}: {percentage:.1f}%|{bar}| {n_fmt}/{total_fmt} [Осталось: {remaining}]") as pbar:
        
        current = start_key
        while current <= end_key:
            private_hex = format(current, '064x')
            if generate_address(private_hex) == target_address:
                found_key = private_hex
                break
            current += 1
            if current % 100000 == 0:  # Обновляем только каждые 1000 ключей
                pbar.update(100000)
        
        # Обновляем оставшиеся ключи
        if current % 100000 != 0:
            pbar.update(current % 100000)
    
    if not found_key:
        checked_ranges.append({
            'start': start_key,
            'end': end_key,
            'checked_at': time.strftime('%Y-%m-%d %H:%M:%S')
        })
        save_checked_ranges(checked_ranges)
    
    return found_key

def main(target_address="1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"):
    checked_ranges = load_checked_ranges()
    total_checked = sum(r['end']-r['start']+1 for r in checked_ranges)
    
    print(f"{Colors.YELLOW}Поиск ключа для адреса: {target_address}{Colors.END}")
    print(f"Уже проверено: {total_checked:,} ключей")
    print(f"Размер блока: {CHUNK_SIZE:,} ключей\n")

    try:
        while True:
            # Генерация случайного непроверенного ключа
            random_key = random.randint(MAIN_START, MAIN_END)
            if is_key_checked(random_key, checked_ranges):
                continue
            
            # Проверка случайного ключа
            random_hex = format(random_key, '064x')
            if generate_address(random_hex) == target_address:
                log_success(random_hex, target_address)
                break
            
            # Проверка последующих ключей
            if (found_key := check_sequential_chunk(random_key, target_address, checked_ranges)):
                log_success(found_key, target_address)
                break
            
            # Проверяем, не проверен ли весь диапазон
            current_coverage = sum(r['end']-r['start']+1 for r in checked_ranges)
            total_range = MAIN_END - MAIN_START + 1
            if current_coverage >= total_range:
                print(f"\n{Colors.RED}Весь диапазон проверен, ключ не найден.{Colors.END}")
                break
            
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Поиск остановлен пользователем{Colors.END}")
    finally:
        print(f"\nИтоги:")
        print(f"Всего проверено: {total_checked + CHUNK_SIZE:,} ключей")
        print(f"Сохранено диапазонов: {len(checked_ranges)}")
        if checked_ranges:
            last_range = checked_ranges[-1]
            print(f"Последний диапазон: {hex(last_range['start'])}-{hex(last_range['end'])}")

if __name__ == "__main__":
    import sys
    main(sys.argv[1] if len(sys.argv) > 1 else "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU")
