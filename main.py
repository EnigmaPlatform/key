import hashlib
import time
import json
import os
import multiprocessing
import coincurve
import signal
import math
import re
from typing import Optional
from collections import Counter

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
    'STATUS_INTERVAL': 60,
    'TARGET_RIPEMD': bytes.fromhex("5db8cda53a6a002db10365967d7f85d19e171b10"),
    'START_KEY': 0x349b84b643196c4ef1,
    'END_KEY': 0x349b84b6431a6c4ef1,
    'BATCH_PER_CORE': 10_000_000,
    'MAX_RETRIES': 3,
    'MIN_ENTROPY': 3.0,
    'PRIORITY_RANGE_PERCENT': 15
}

def init_shared_stats(s):
    global shared_stats
    shared_stats = s

def calculate_entropy(s: str) -> float:
    """Вычисляет энтропию строки в битах на символ."""
    freq = {}
    for char in s:
        freq[char] = freq.get(char, 0) + 1
    entropy = -sum((f / len(s)) * math.log2(f / len(s)) for f in freq.values())
    return entropy

def is_junk_key(key_hex: str) -> bool:
    """Проверяет ключ на наличие нежелательных паттернов."""
    significant_part = key_hex.lstrip('0')[-18:]  # Берем значимую часть без ведущих нулей
    
    # 1. Проверка на 60+ ведущих нулей
    if not key_hex.startswith('0'*60):
        return True
    
    # 2. Проверка на повторяющиеся последовательности (4+ одинаковых символа)
    if re.search(r'(.)\1{3}', significant_part):
        return True
    
    # 3. Проверка на тривиальные последовательности
    trivial_sequences = [
        '0123', '1234', '2345', '3456', '4567', '5678', '6789',
        '89ab', '9abc', 'abcd', 'bcde', 'cdef', 'def0', 'fedc',
        '0000', '1111', '2222', '3333', '4444', '5555', '6666',
        '7777', '8888', '9999', 'aaaa', 'bbbb', 'cccc', 'dddd',
        'eeee', 'ffff'
    ]
    if any(seq in significant_part for seq in trivial_sequences):
        return True
    
    # 4. Проверка на низкую энтропию
    if len(significant_part) >= 8 and calculate_entropy(significant_part) < CONFIG['MIN_ENTROPY']:
        return True
    
    # 5. Проверка на "мемные" значения
    meme_values = ['dead', 'beef', 'cafe', 'face', 'bad', 'feed', 'ace', 'add']
    if any(meme in significant_part for meme in meme_values):
        return True
    
    # 6. Проверка на слишком простые ключи (ИСПРАВЛЕННАЯ ЧАСТЬ)
    hex_digits = set(significant_part.lower())
    if hex_digits.issubset(set('01234567')) or hex_digits.issubset(set('89abcdef')):
        return True
    
    # 7. Проверка контрольной суммы (сумма последних 16 символов кратна 8)
    if len(significant_part) >= 16:
        last_16 = significant_part[-16:]
        if sum(int(c, 16) for c in last_16) % 8 != 0:
            return True
    
    return False

def key_to_ripemd160(private_key_hex: str) -> Optional[bytes]:
    """Конвертирует приватный ключ в RIPEMD-160 хеш адреса."""
    try:
        priv = bytes.fromhex(private_key_hex)
        pub_key = coincurve.PublicKey.from_valid_secret(priv).format(compressed=True)
        sha256 = hashlib.sha256(pub_key).digest()
        return hashlib.new('ripemd160', sha256).digest()
    except Exception:
        return None

def load_checkpoint() -> int:
    """Загружает последнюю позицию из файла чекпоинта."""
    if not os.path.exists(CONFIG['CHECKPOINT_FILE']):
        return CONFIG['START_KEY']
    
    for attempt in range(CONFIG['MAX_RETRIES']):
        try:
            with open(CONFIG['CHECKPOINT_FILE'], 'r') as f:
                data = json.load(f)
                last_key = int(data['last_key'], 16)
                
                if last_key < CONFIG['START_KEY']:
                    print(f"{Colors.YELLOW}Checkpoint before start key, resetting to start{Colors.END}")
                    return CONFIG['START_KEY']
                elif last_key >= CONFIG['END_KEY']:
                    print(f"{Colors.YELLOW}Checkpoint at end key, resetting to start{Colors.END}")
                    return CONFIG['START_KEY']
                    
                return last_key + 1
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            print(f"{Colors.RED}Checkpoint error (attempt {attempt+1}): {e}{Colors.END}")
            time.sleep(1)
    
    print(f"{Colors.RED}Fatal: Could not load checkpoint{Colors.END}")
    return CONFIG['START_KEY']

def atomic_save_checkpoint(current_key: int, stats):
    """Атомарно сохраняет текущую позицию в файл."""
    temp_file = f"{CONFIG['CHECKPOINT_FILE']}.{os.getpid()}.tmp"
    data = {
        'last_key': hex(current_key),
        'timestamp': time.time(),
        'stats': dict(stats)
    }
    
    for attempt in range(CONFIG['MAX_RETRIES']):
        try:
            with open(temp_file, 'w') as f:
                json.dump(data, f)
            os.replace(temp_file, CONFIG['CHECKPOINT_FILE'])
            return
        except Exception as e:
            print(f"{Colors.RED}Save error (attempt {attempt+1}): {e}{Colors.END}")
            time.sleep(1)
    
    print(f"{Colors.RED}Fatal: Failed to save checkpoint{Colors.END}")

def process_key_batch(start_key: int, end_key: int, target: bytes, stats):
    """Обрабатывает пакет ключей в одном процессе."""
    local_checked = 0
    local_skipped = 0
    
    # Определяем, находимся ли мы в приоритетном диапазоне
    priority_threshold = CONFIG['END_KEY'] - (CONFIG['END_KEY'] - CONFIG['START_KEY']) * CONFIG['PRIORITY_RANGE_PERCENT'] // 100
    is_priority_range = end_key >= priority_threshold
    
    # Для приоритетного диапазона идем в обратном порядке
    if is_priority_range:
        keys = range(end_key, start_key - 1, -1)
    else:
        keys = range(start_key, end_key + 1)
    
    for k in keys:
        private_key = f"{k:064x}"
        
        if not is_priority_range and is_junk_key(private_key):
            local_skipped += 1
            continue
            
        if (ripemd := key_to_ripemd160(private_key)) and ripemd == target:
            stats['keys_found'] += 1
            return private_key
        
        local_checked += 1
        if local_checked % 100_000 == 0:
            stats['keys_checked'] += local_checked
            stats['keys_skipped'] += local_skipped
            local_checked = 0
            local_skipped = 0
    
    stats['keys_checked'] += local_checked
    stats['keys_skipped'] += local_skipped
    return None

class KeySearcher:
    def __init__(self):
        self.current_key = load_checkpoint()
        self.should_stop = False
        self.start_time = time.time()
        signal.signal(signal.SIGINT, self.handle_interrupt)
        signal.signal(signal.SIGTERM, self.handle_interrupt)

    def handle_interrupt(self, signum, frame):
        print(f"\n{Colors.YELLOW}Received interrupt signal, saving progress...{Colors.END}")
        self.should_stop = True

    def print_status(self, stats):
        """Выводит текущий статус поиска."""
        elapsed = time.time() - self.start_time
        keys_per_sec = stats['keys_checked'] / max(elapsed, 1)
        
        # Расчет оставшегося времени
        remaining_keys = CONFIG['END_KEY'] - self.current_key
        remaining_time = remaining_keys / max(keys_per_sec, 1)
        
        print(
            f"{Colors.BLUE}[Status]{Colors.END} "
            f"Keys: {Colors.YELLOW}{stats['keys_checked']:,}{Colors.END} | "
            f"Skipped: {stats['keys_skipped']:,} | "
            f"Speed: {self.format_speed(keys_per_sec)} | "
            f"Progress: {self.get_progress():.2f}% | "
            f"Elapsed: {elapsed/3600:.1f}h | "
            f"Remaining: {remaining_time/3600:.1f}h | "
            f"Current: {hex(self.current_key)[:12]}..."
        )

    def format_speed(self, speed: float) -> str:
        """Форматирует скорость перебора."""
        if speed > 1_000_000:
            return f"{Colors.GREEN}{speed/1_000_000:.2f}M{Colors.END}"
        elif speed > 100_000:
            return f"{Colors.YELLOW}{speed/1_000:.0f}K{Colors.END}"
        return f"{Colors.RED}{speed:,.0f}{Colors.END}"

    def get_progress(self) -> float:
        """Вычисляет процент выполнения."""
        total = CONFIG['END_KEY'] - CONFIG['START_KEY']
        done = self.current_key - CONFIG['START_KEY']
        return min(100.0, done / total * 100) if total > 0 else 0

    def run(self):
        """Основной цикл поиска ключей."""
        print(f"{Colors.BLUE}=== Bitcoin Puzzle Solver ==={Colors.END}")
        print(f"Target: {Colors.YELLOW}{CONFIG['TARGET_RIPEMD'].hex()}{Colors.END}")
        print(f"Range: {Colors.YELLOW}{hex(CONFIG['START_KEY'])} - {hex(CONFIG['END_KEY'])}{Colors.END}")
        print(f"Priority search: top {CONFIG['PRIORITY_RANGE_PERCENT']}% of range")
        print(f"Filters: entropy > {CONFIG['MIN_ENTROPY']}, pattern checks, checksum validation")
        
        if self.current_key > CONFIG['START_KEY']:
            print(f"{Colors.GREEN}Resuming from checkpoint: {hex(self.current_key)}{Colors.END}")
        
        num_cores = multiprocessing.cpu_count()
        print(f"Using {num_cores} CPU cores")
        
        manager = multiprocessing.Manager()
        shared_stats = manager.dict({
            'keys_checked': 0,
            'keys_found': 0,
            'keys_skipped': 0
        })
        
        pool = multiprocessing.Pool(processes=num_cores, initializer=init_shared_stats, initargs=(shared_stats,))
        last_status_time = time.time()
        found_key = None
        
        try:
            while self.current_key <= CONFIG['END_KEY'] and not found_key and not self.should_stop:
                # Динамический размер пакета
                current_percent = (self.current_key - CONFIG['START_KEY']) / (CONFIG['END_KEY'] - CONFIG['START_KEY'])
                if current_percent > 0.85:  # Верхние 15%
                    batch_size = CONFIG['BATCH_PER_CORE'] * num_cores
                else:
                    batch_size = CONFIG['BATCH_PER_CORE'] * num_cores * 4
                
                batch_end = min(self.current_key + batch_size - 1, CONFIG['END_KEY'])
                
                # Распределение задач
                keys_per_core = (batch_end - self.current_key + 1) // num_cores
                tasks = []
                for i in range(num_cores):
                    start = self.current_key + i * keys_per_core
                    end = start + keys_per_core - 1 if i < num_cores - 1 else batch_end
                    tasks.append((start, end, CONFIG['TARGET_RIPEMD'], shared_stats))
                
                # Параллельное выполнение
                results = pool.starmap(process_key_batch, tasks)
                
                # Проверка результатов
                for result in results:
                    if result:
                        found_key = result
                        break
                
                self.current_key = batch_end + 1
                
                # Сохранение прогресса
                if shared_stats['keys_checked'] % CONFIG['SAVE_INTERVAL'] == 0:
                    atomic_save_checkpoint(self.current_key - 1, shared_stats)
                
                # Вывод статуса
                if time.time() - last_status_time >= CONFIG['STATUS_INTERVAL']:
                    self.print_status(shared_stats)
                    last_status_time = time.time()
            
            # Обработка результатов
            if found_key:
                print(f"\n{Colors.GREEN}>>> KEY FOUND! <<<{Colors.END}")
                print(f"Private: {Colors.YELLOW}{found_key}{Colors.END}")
                print(f"Address: {key_to_ripemd160(found_key).hex() if key_to_ripemd160(found_key) else 'Unknown'}")
                
                with open(CONFIG['FOUND_KEYS_FILE'], 'a') as f:
                    f.write(f"\n{time.ctime()}\n")
                    f.write(f"Private: {found_key}\n")
                    f.write(f"RIPEMD: {CONFIG['TARGET_RIPEMD'].hex()}\n")
            elif self.should_stop:
                print(f"\n{Colors.YELLOW}Search stopped by user{Colors.END}")
            else:
                print(f"\n{Colors.BLUE}Search completed - key not found{Colors.END}")
                
        except Exception as e:
            print(f"\n{Colors.RED}Fatal error: {e}{Colors.END}")
        finally:
            pool.close()
            pool.join()
            
            if not found_key and self.current_key > CONFIG['START_KEY']:
                atomic_save_checkpoint(self.current_key - 1, shared_stats)
            
            elapsed = time.time() - self.start_time
            total_checked = shared_stats['keys_checked']
            keys_per_sec = total_checked / max(elapsed, 1)
            
            print(f"\n{Colors.BLUE}=== Final Statistics ===")
            print(f"Total keys checked: {total_checked:,}")
            print(f"Total keys skipped: {shared_stats['keys_skipped']:,}")
            print(f"Total time: {elapsed/3600:.2f} hours")
            print(f"Average speed: {self.format_speed(keys_per_sec)}")
            print(f"Last checked key: {hex(self.current_key)}")
            print(f"==================={Colors.END}")

if __name__ == "__main__":
    multiprocessing.freeze_support()
    searcher = KeySearcher()
    searcher.run()
