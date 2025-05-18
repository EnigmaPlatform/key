import hashlib
import random
import base58
import ecdsa
import time
import json
import os
from tqdm import tqdm
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor
from intervaltree import IntervalTree
import signal

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    END = '\033[0m'

# Конфигурация
CHECKPOINT_FILE = "checked_ranges.json"
FOUND_KEYS_FILE = "found_keys.txt"
CHUNK_SIZE = 10_000_000  # Размер проверяемого блока
MAIN_START = 0x349b84b6431a6c0ef1  # Начало диапазона
MAIN_END = 0x349b84b6431a6c4ef9    # Конец диапазона
BATCH_SIZE = 1000                  # Размер пакета для многопоточной обработки
MAX_WORKERS = 4                    # Количество потоков
SAVE_INTERVAL = 10                 # Интервал сохранения (в блоках)

# Глобальные переменные для обработки прерываний
stop_flag = False
current_chunk = None

def init_checked_ranges():
    """Инициализация структуры для хранения проверенных диапазонов"""
    if os.path.exists(CHECKPOINT_FILE):
        try:
            with open(CHECKPOINT_FILE, 'r') as f:
                data = json.load(f)
                tree = IntervalTree()
                for item in data:
                    tree.addi(item['start'], item['end']+1, item)
                return tree
        except:
            return IntervalTree()
    return IntervalTree()

def save_checked_ranges(tree):
    """Сохранение проверенных диапазонов"""
    data = [{'start': iv.begin, 'end': iv.end-1, 'checked_at': iv.data['checked_at']} 
            for iv in tree]
    with open(CHECKPOINT_FILE, 'w') as f:
        json.dump(data, f, indent=2)

@lru_cache(maxsize=100000)
def generate_address(private_key_hex):
    """Генерация Bitcoin-адреса с кешированием"""
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

def check_batch(batch, target):
    """Проверка пакета ключей в нескольких потоках"""
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        results = list(executor.map(generate_address, batch))
        if target in results:
            return batch[results.index(target)]
    return None

def check_sequential_chunk(start_key, target_address, checked_ranges):
    """Проверка последовательного блока ключей"""
    global stop_flag, current_chunk
    
    end_key = min(start_key + CHUNK_SIZE - 1, MAIN_END)
    current_chunk = (start_key, end_key)
    
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
            
            if found_key := check_batch(batch, target_address):
                return found_key
                
            pbar.update(batch_end - batch_start + 1)
    
    if not stop_flag:
        checked_ranges.addi(start_key, end_key+1, {
            'checked_at': time.strftime('%Y-%m-%d %H:%M:%S')
        })
        if len(checked_ranges) % SAVE_INTERVAL == 0:
            save_checked_ranges(checked_ranges)
    
    return None

def signal_handler(sig, frame):
    """Обработчик сигнала прерывания"""
    global stop_flag
    print(f"\n{Colors.YELLOW}Получен сигнал прерывания...{Colors.END}")
    stop_flag = True

def main(target_address="19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR"):
    """Основная функция поиска"""
    global stop_flag
    
    # Настройка обработчика прерываний
    signal.signal(signal.SIGINT, signal_handler)
    
    checked_ranges = init_checked_ranges()
    total_checked = sum(iv.end-iv.begin for iv in checked_ranges)
    
    print(f"{Colors.YELLOW}Поиск ключа для адреса: {target_address}{Colors.END}")
    print(f"Уже проверено: {total_checked:,} ключей")
    print(f"Размер блока: {CHUNK_SIZE:,} ключей")
    print(f"Потоков: {MAX_WORKERS}, Пакет: {BATCH_SIZE} ключей\n")

    try:
        while not stop_flag:
            # Генерация случайного непроверенного ключа
            attempts = 0
            while not stop_flag:
                random_key = random.randint(MAIN_START, MAIN_END)
                if not checked_ranges.overlaps(random_key):
                    break
                attempts += 1
                if attempts > 1000:
                    print(f"{Colors.RED}Не удалось найти непроверенный ключ{Colors.END}")
                    stop_flag = True
                    break
            
            if stop_flag:
                break
                
            # Проверка случайного ключа
            random_hex = format(random_key, '064x')
            if generate_address(random_hex) == target_address:
                print(f"\n{Colors.GREEN}Ключ найден в случайной точке!{Colors.END}")
                print(f"Приватный ключ: {random_hex}")
                break
                
            # Проверка последовательного блока
            if found_key := check_sequential_chunk(random_key, target_address, checked_ranges):
                print(f"\n{Colors.GREEN}Ключ найден в последовательном блоке!{Colors.END}")
                print(f"Приватный ключ: {found_key}")
                break
                
            # Проверка завершения всего диапазона
            if sum(iv.end-iv.begin for iv in checked_ranges) >= (MAIN_END - MAIN_START + 1):
                print(f"\n{Colors.RED}Весь диапазон проверен, ключ не найден.{Colors.END}")
                break
                
    except Exception as e:
        print(f"\n{Colors.RED}Ошибка: {e}{Colors.END}")
    finally:
        # Финализация
        if not stop_flag and current_chunk:
            checked_ranges.addi(current_chunk[0], current_chunk[1]+1, {
                'checked_at': time.strftime('%Y-%m-%d %H:%M:%S')
            })
        
        save_checked_ranges(checked_ranges)
        total_checked = sum(iv.end-iv.begin for iv in checked_ranges)
        
        print(f"\n{Colors.YELLOW}Итоги:{Colors.END}")
        print(f"Всего проверено: {total_checked:,} ключей")
        print(f"Сохранено диапазонов: {len(checked_ranges)}")
        
        if checked_ranges:
            last_range = max(checked_ranges, key=lambda iv: iv.end)
            print(f"Последний диапазон: {hex(last_range.begin)}-{hex(last_range.end-1)}")

if __name__ == "__main__":
    import sys
    main(sys.argv[1] if len(sys.argv) > 1 else "19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR")
