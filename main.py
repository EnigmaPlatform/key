import hashlib
import time
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
    'FOUND_KEYS_FILE': "found_keys.txt",
    'TARGET_RIPEMD': bytes.fromhex("f6f5431d25bbf7b12e8add9af5e3475c44a0a5b8"),
    'START_KEY': 0x20000000000000000,
    'END_KEY': 0x3ffffffffffffffff,
    'BATCH_PER_CORE': 1_000,
    'MIN_ENTROPY': 3.0,
    'PRIORITY_RANGE_PERCENT': 15,
    'UPDATE_INTERVAL': 1_000_000
}

TRIVIAL_SEQUENCES = re.compile(r'(0123|1234|2345|3456|4567|5678|6789|89ab|9abc|abcd|bcde|cdef|def0|fedc|0000|1111|2222|3333|4444|5555|6666|7777|8888|9999|aaaa|bbbb|cccc|dddd|eeee|ffff)')
MEME_VALUES = re.compile(r'(dead|beef|cafe|face|bad|feed|ace|add)')
REPEATING_CHARS = re.compile(r'(.)\1{3}')

def init_shared_stats(s):
    global shared_stats
    shared_stats = s

@lru_cache(maxsize=10000)
def calculate_entropy(s: str) -> float:
    freq = Counter(s)
    total = len(s)
    return -sum((count/total) * math.log2(count/total) for count in freq.values())

def is_junk_key(key_hex: str) -> bool:
    if not key_hex.startswith('0'*46):
        return True
    
    part = key_hex[-18:]
    if (REPEATING_CHARS.search(part) or 
        TRIVIAL_SEQUENCES.search(part) or 
        MEME_VALUES.search(part)):
        return True
        
    digits = set(part.lower())
    if digits.issubset(set('01234567')) or digits.issubset(set('89abcdef')):
        return True
        
    if len(part) >= 16 and sum(int(c, 16) for c in part[-16:]) % 8 != 0:
        return True
            
    return len(part) >= 8 and calculate_entropy(part) < CONFIG['MIN_ENTROPY']

def key_to_ripemd160(private_key_hex: str) -> Optional[bytes]:
    try:
        priv = bytes.fromhex(private_key_hex)
        pub_key = coincurve.PublicKey.from_secret(priv).format(compressed=True)
        sha256 = hashlib.sha256(pub_key).digest()
        return hashlib.new('ripemd160', sha256).digest()
    except Exception:
        return None

def verify_hash_function():
    test_key = "0000000000000000000000000000000000000000000000000000000000000001"
    expected = "751e76e8199196d454941c45d1b3a323f1433bd6"
    result = key_to_ripemd160(test_key)
    
    if not result or result.hex() != expected:
        print(f"{Colors.RED}Ошибка проверки хеша!{Colors.END}")
        print(f"Ожидалось: {expected}")
        print(f"Получено: {result.hex() if result else 'None'}")
        return False
    
    print(f"{Colors.GREEN}Проверка хеша успешна{Colors.END}")
    return True

def process_key_batch(start_key: int, end_key: int, target: bytes, stats):
    local_checked = local_skipped = 0
    threshold = CONFIG['END_KEY'] - (CONFIG['END_KEY'] - CONFIG['START_KEY']) * CONFIG['PRIORITY_RANGE_PERCENT'] // 100
    is_priority = end_key >= threshold
    step = -1 if is_priority else 1
    current = end_key if is_priority else start_key
    end = start_key - 1 if is_priority else end_key + 1
    
    while current != end:
        key_hex = f"{current:064x}"
        
        if not is_priority and is_junk_key(key_hex):
            local_skipped += 1
        else:
            if (ripemd := key_to_ripemd160(key_hex)) and ripemd == target:
                stats['keys_found'] += 1
                return key_hex
            local_checked += 1
            
        if local_checked % 100_000 == 0:
            stats['keys_checked'] += local_checked
            stats['keys_skipped'] += local_skipped
            local_checked = local_skipped = 0
            
        current += step
    
    stats['keys_checked'] += local_checked
    stats['keys_skipped'] += local_skipped
    return None

class KeySearcher:
    def __init__(self):
        self.current_key = CONFIG['START_KEY']
        self.should_stop = False
        self.start_time = time.time()
        self.last_update = 0
        signal.signal(signal.SIGINT, self.handle_interrupt)
        signal.signal(signal.SIGTERM, self.handle_interrupt)

    def handle_interrupt(self, signum, frame):
        print(f"\n{Colors.YELLOW}Получен сигнал прерывания, остановка...{Colors.END}")
        self.should_stop = True

    def print_status(self, stats):
        elapsed = time.time() - self.start_time
        keys_per_sec = stats['keys_checked'] / max(elapsed, 1)
        remaining = CONFIG['END_KEY'] - self.current_key
        remaining_time = remaining / max(keys_per_sec, 1)
        
        print(f"\n{Colors.BLUE}=== Статус ===")
        print(f"Проверено: {Colors.YELLOW}{stats['keys_checked']:,}{Colors.END}")
        print(f"Пропущено: {stats['keys_skipped']:,}")
        print(f"Скорость: {self._format_speed(keys_per_sec)}/сек")
        print(f"Прогресс: {self._get_progress():.2f}%")
        print(f"Прошло: {elapsed/3600:.1f} ч")
        print(f"Осталось: {remaining_time/3600:.1f} ч")
        print(f"Текущий ключ: {hex(self.current_key)}")
        print(f"============={Colors.END}\n")

    def _format_speed(self, speed):
        if speed > 1_000_000:
            return f"{Colors.GREEN}{speed/1_000_000:.1f}M{Colors.END}"
        return f"{Colors.YELLOW}{speed/1_000:.0f}K{Colors.END}" if speed > 1000 else f"{speed:,.0f}"

    def _get_progress(self):
        total = CONFIG['END_KEY'] - CONFIG['START_KEY']
        done = self.current_key - CONFIG['START_KEY']
        return min(100.0, done / total * 100) if total > 0 else 0

    def run(self):
        print(f"{Colors.BLUE}=== Bitcoin Puzzle Solver ==={Colors.END}")
        print(f"Цель: {Colors.YELLOW}{CONFIG['TARGET_RIPEMD'].hex()}{Colors.END}")
        print(f"Диапазон: {hex(CONFIG['START_KEY'])} - {hex(CONFIG['END_KEY'])}")
        
        if not verify_hash_function():
            return

        num_cores = multiprocessing.cpu_count()
        print(f"Используется процессов: {num_cores * 2} (ядер: {num_cores})")
        
        with multiprocessing.Manager() as manager:
            stats = manager.dict({'keys_checked': 0, 'keys_found': 0, 'keys_skipped': 0})
            
            with multiprocessing.Pool(processes=num_cores*2, initializer=init_shared_stats, initargs=(stats,)) as pool:
                try:
                    while self.current_key <= CONFIG['END_KEY'] and not self.should_stop:
                        batch_end = min(self.current_key + CONFIG['BATCH_PER_CORE'] * num_cores - 1, CONFIG['END_KEY'])
                        tasks = []
                        
                        for i in range(num_cores * 2):
                            start = self.current_key + i * (batch_end - self.current_key + 1) // (num_cores * 2)
                            end = start + (batch_end - self.current_key + 1) // (num_cores * 2) - 1 if i < num_cores * 2 - 1 else batch_end
                            tasks.append((start, end, CONFIG['TARGET_RIPEMD'], stats))
                        
                        for result in pool.starmap(process_key_batch, tasks):
                            if result:
                                self._handle_found_key(result)
                                return
                        
                        self.current_key = batch_end + 1
                        
                        if stats['keys_checked'] - self.last_update >= CONFIG['UPDATE_INTERVAL']:
                            self.print_status(stats)
                            self.last_update = stats['keys_checked']
                    
                    self.print_status(stats)
                    print(f"{Colors.BLUE}Поиск завершен - ключ не найден{Colors.END}")
                
                except Exception as e:
                    print(f"{Colors.RED}Ошибка: {e}{Colors.END}")

    def _handle_found_key(self, key):
        print(f"\n{Colors.GREEN}>>> КЛЮЧ НАЙДЕН! <<<{Colors.END}")
        print(f"Приватный ключ: {Colors.YELLOW}{key}{Colors.END}")
        print(f"Адрес: {key_to_ripemd160(key).hex()}")
        
        with open(CONFIG['FOUND_KEYS_FILE'], 'a') as f:
            f.write(f"\n{time.ctime()}\nПриватный ключ: {key}\nRIPEMD: {CONFIG['TARGET_RIPEMD'].hex()}\n")

if __name__ == "__main__":
    if os.name == 'posix':
        multiprocessing.set_start_method('fork')
    
    searcher = KeySearcher()
    searcher.run()
