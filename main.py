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
    'STATUS_INTERVAL': 60,
    'TARGET_RIPEMD': bytes.fromhex("f6f5431d25bbf7b12e8add9af5e3475c44a0a5b8"),
    'START_KEY': 0x6fffffffffffffffff,
    'END_KEY': 0x7fffffffffffffffff,
    'BATCH_PER_CORE': 1_000_000,
    'MAX_RETRIES': 3,
    'MIN_ENTROPY': 3.0,
    'PRIORITY_RANGE_PERCENT': 15
}

# Предварительно компилируем регулярные выражения
TRIVIAL_SEQUENCES = re.compile(
    r'(0123|1234|2345|3456|4567|5678|6789|89ab|9abc|abcd|bcde|cdef|def0|fedc|'
    r'0000|1111|2222|3333|4444|5555|6666|7777|8888|9999|aaaa|bbbb|cccc|dddd|eeee|ffff)'
)
MEME_VALUES = re.compile(r'(dead|beef|cafe|face|bad|feed|ace|add)')
REPEATING_CHARS = re.compile(r'(.)\1{3}')

def init_shared_stats(s):
    global shared_stats
    shared_stats = s

@lru_cache(maxsize=10000)
def calculate_entropy(s: str) -> float:
    """Кэшируем вычисление энтропии для часто встречающихся строк"""
    freq = Counter(s)
    total = len(s)
    return -sum((count/total) * math.log2(count/total) for count in freq.values())

def is_junk_key(key_hex: str) -> bool:
    """Оптимизированная проверка ключа"""
    if not key_hex.startswith('0'*46):
        return True
    
    significant_part = key_hex[-18:]
    
    # Быстрые проверки в порядке увеличения сложности
    if REPEATING_CHARS.search(significant_part):
        return True
        
    if TRIVIAL_SEQUENCES.search(significant_part):
        return True
        
    if MEME_VALUES.search(significant_part):
        return True
        
    hex_digits = set(significant_part.lower())
    if hex_digits.issubset(set('01234567')) or hex_digits.issubset(set('89abcdef')):
        return True
        
    if len(significant_part) >= 16:
        last_16 = significant_part[-16:]
        if sum(int(c, 16) for c in last_16) % 8 != 0:
            return True
            
    if len(significant_part) >= 8 and calculate_entropy(significant_part) < CONFIG['MIN_ENTROPY']:
        return True
    
    return False

def key_to_ripemd160(private_key_hex: str) -> Optional[bytes]:
    """Оптимизированная конвертация ключа"""
    try:
        priv = bytes.fromhex(private_key_hex)
        pub_key = coincurve.PublicKey.from_secret(priv).format(compressed=True)
        sha256 = hashlib.sha256(pub_key).digest()
        return hashlib.new('ripemd160', sha256, usedforsecurity=False).digest()
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
    """Оптимизированная обработка пакета ключей"""
    local_checked = 0
    local_skipped = 0
    
    priority_threshold = CONFIG['END_KEY'] - (CONFIG['END_KEY'] - CONFIG['START_KEY']) * CONFIG['PRIORITY_RANGE_PERCENT'] // 100
    is_priority_range = end_key >= priority_threshold
    
    step = -1 if is_priority_range else 1
    current = end_key if is_priority_range else start_key
    end = start_key - 1 if is_priority_range else end_key + 1
    
    while current != end:
        private_key = f"{current:064x}"
        
        if not is_priority_range and is_junk_key(private_key):
            local_skipped += 1
        else:
            if (ripemd := key_to_ripemd160(private_key)) and ripemd == target:
                stats['keys_found'] += 1
                return private_key
            local_checked += 1
            
        if local_checked % 1_000_000 == 0:
            stats['keys_checked'] += local_checked
            stats['keys_skipped'] += local_skipped
            local_checked = 0
            local_skipped = 0
            
        current += step
    
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
        """Выводит текущий статус поиска с полным отображением текущего ключа"""
        elapsed = time.time() - self.start_time
        keys_per_sec = stats['keys_checked'] / max(elapsed, 1)
        
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
            f"Current: {hex(self.current_key)}"
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
                current_percent = (self.current_key - CONFIG['START_KEY']) / (CONFIG['END_KEY'] - CONFIG['START_KEY'])
                if current_percent > 0.85:
                    batch_size = CONFIG['BATCH_PER_CORE'] * num_cores
                else:
                    batch_size = CONFIG['BATCH_PER_CORE'] * num_cores * 4
                
                batch_end = min(self.current_key + batch_size - 1, CONFIG['END_KEY'])
                
                keys_per_core = (batch_end - self.current_key + 1) // num_cores
                tasks = []
                for i in range(num_cores):
                    start = self.current_key + i * keys_per_core
                    end = start + keys_per_core - 1 if i < num_cores - 1 else batch_end
                    tasks.append((start, end, CONFIG['TARGET_RIPEMD'], shared_stats))
                
                results = pool.starmap(process_key_batch, tasks)
                
                for result in results:
                    if result:
                        found_key = result
                        break
                
                self.current_key = batch_end + 1
                
                if shared_stats['keys_checked'] % CONFIG['SAVE_INTERVAL'] == 0:
                    atomic_save_checkpoint(self.current_key - 1, shared_stats)
                
                if time.time() - last_status_time >= CONFIG['STATUS_INTERVAL']:
                    self.print_status(shared_stats)
                    last_status_time = time.time()
            
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
    if os.name == 'posix':
        multiprocessing.set_start_method('fork')
        
    multiprocessing.freeze_support()
    searcher = KeySearcher()
    searcher.run()
