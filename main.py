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
    'MAX_WORKERS': max(4, multiprocessing.cpu_count()),  # Не более CPU ядер
    'STATUS_INTERVAL': 30,
    'TARGET_ADDRESS': "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU",
    'START': 0x1A12F1DA9D7000000,
    'END': 0x1A12F1DA9DFFFFFFF,
    'HEX_PATTERN': '1a12f1d',
    'BANNED_SUFFIXES': ['aaaa', 'ffff'],
    'BIT_TRANSITIONS_RANGE': (7, 9),
    'HEX_LENGTH': 16  # Длина hex-представления ключа
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

def count_bit_transitions(key: int) -> int:
    """Быстрый подсчет битовых переходов (0->1 или 1->0)"""
    xor = key ^ (key >> 1)
    return bin(xor).count('1')

def is_valid_key(key: int) -> bool:
    """Оптимизированная проверка ключа"""
    hex_key = f"{key:0{CONFIG['HEX_LENGTH']}x}"
    
    # Быстрые проверки в порядке возрастания сложности
    if not CONFIG['HEX_PATTERN'] in hex_key:
        return False
        
    if any(hex_key.endswith(s) for s in CONFIG['BANNED_SUFFIXES']):
        return False
        
    transitions = count_bit_transitions(key)
    if not CONFIG['BIT_TRANSITIONS_RANGE'][0] <= transitions <= CONFIG['BIT_TRANSITIONS_RANGE'][1]:
        return False
        
    return True

@lru_cache(maxsize=1_000_000)
def private_to_address(private_key_hex: str) -> Optional[str]:
    """Кэшированное преобразование приватного ключа в адрес"""
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
            
            if start > end:  # Исключаем некорректные диапазоны
                continue
                
            chunks.append((start, end))
    
    return sorted(chunks, key=lambda x: x[0])  # Сортируем по началу диапазона

def process_chunk(start: int, end: int) -> Tuple[int, int, Optional[Tuple[int, str]]]:
    """Обрабатывает чанк ключей, возвращает статистику и найденный ключ"""
    start_time = time.time()
    last_log_time = time.time()
    valid_keys_checked = 0
    total_keys_checked = 0
    
    for key in range(start, end + 1):
        total_keys_checked += 1
        
        if not is_valid_key(key):
            continue
            
        valid_keys_checked += 1
        private_key = f"{key:0{CONFIG['HEX_LENGTH']}x}"
        address = private_to_address(private_key)
        
        if address == CONFIG['TARGET_ADDRESS']:
            return (total_keys_checked, valid_keys_checked, (key, private_key))
        
        # Логирование прогресса
        if time.time() - last_log_time > CONFIG['STATUS_INTERVAL']:
            speed = int(total_keys_checked / max(1, time.time() - start_time))
            print(f"{Colors.CYAN}[PID {os.getpid()}] {hex(key)} | "
                  f"Speed: {speed:,} keys/s | "
                  f"Valid: {valid_keys_checked:,}{Colors.END}")
            last_log_time = time.time()
    
    return (total_keys_checked, valid_keys_checked, None)

def format_time(seconds: float) -> str:
    """Форматирует время в читаемый вид"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{seconds // 60:.0f}m {seconds % 60:.0f}s"
    else:
        return f"{seconds // 3600:.0f}h {(seconds % 3600) // 60:.0f}m"

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
    total_keys_processed = 0
    total_valid_keys = 0
    
    with ProcessPoolExecutor(max_workers=CONFIG['MAX_WORKERS'], initializer=init_worker) as executor:
        futures = {executor.submit(process_chunk, start, end): (start, end) for start, end in chunks}
        
        for future in as_completed(futures):
            start, end = futures[future]
            processed_chunks += 1
            chunk_keys, chunk_valid_keys, result = future.result()
            
            total_keys_processed += chunk_keys
            total_valid_keys += chunk_valid_keys
            
            # Расчет статистики
            elapsed = time.time() - start_time
            total_keys = CONFIG['END'] - CONFIG['START'] + 1
            percent = min(100, (total_keys_processed / total_keys) * 100)
            speed = int(total_keys_processed / elapsed) if elapsed > 0 else 0
            valid_percent = (total_valid_keys / total_keys_processed * 100) if total_keys_processed > 0 else 0
            eta = (total_keys - total_keys_processed) / speed if speed > 0 else 0
            
            print(f"\n{Colors.YELLOW}=== Прогресс ===")
            print(f"Чанков: {processed_chunks}/{total_chunks}")
            print(f"Ключей: {total_keys_processed:,}/{total_keys:,} ({percent:.2f}%)")
            print(f"Валидных ключей: {total_valid_keys:,} ({valid_percent:.2f}%)")
            print(f"Скорость: {speed:,} keys/s")
            print(f"Прошло времени: {format_time(elapsed)}")
            print(f"Осталось времени: {format_time(eta)}")
            print(f"Текущий диапазон: {hex(start)}-{hex(end)}")
            print(f"=================={Colors.END}")
            
            if result:
                key, private_key = result
                print(f"\n{Colors.GREEN}>>> КЛЮЧ НАЙДЕН! <<<{Colors.END}")
                print(f"Приватный ключ: {private_key}")
                print(f"Hex: {hex(key)}")
                with open(CONFIG['FOUND_KEYS_FILE'], 'w') as f:
                    f.write(f"Адрес: {CONFIG['TARGET_ADDRESS']}\n")
                    f.write(f"Ключ: {private_key}\n")
                    f.write(f"Hex: {hex(key)}\n")
                # Останавливаем другие процессы
                for f in futures:
                    f.cancel()
                return
            
            # Сохраняем прогресс
            checked_ranges.append({
                'start': start,
                'end': end,
                'time': time.time(),
                'keys_checked': chunk_keys,
                'valid_keys': chunk_valid_keys
            })
            save_checked_ranges(checked_ranges)
    
    print(f"\n{Colors.BLUE}Поиск завершен. Ключ не найден.{Colors.END}")
    print(f"Всего проверено ключей: {total_keys_processed:,}")
    print(f"Валидных ключей: {total_valid_keys:,}")
    save_checked_ranges(checked_ranges)

if __name__ == "__main__":
    multiprocessing.freeze_support()
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}Программа остановлена пользователем.{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.RED}Критическая ошибка: {e}{Colors.END}")
