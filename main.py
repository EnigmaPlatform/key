import hashlib
import base58
import time
import json
import os
import multiprocessing
import coincurve
import signal
from typing import Optional

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
    'TARGET_ADDRESS': "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU",
    'START_KEY': 0x700000000000000000,
    'END_KEY': 0x7fffffffffffffffff,
    'BATCH_PER_CORE': 5_000_000,
    'MAX_RETRIES': 3
}

def init_shared_stats(s, l):
    global shared_stats, stats_lock
    shared_stats = s
    stats_lock = l

def is_junk_key(key_hex: str) -> bool:
    """Улучшенная проверка на невалидные ключи"""
    key_hex = key_hex.lstrip('0') or '0'
    
    # 1. Длинные последовательности (6+ одинаковых символа)
    for c in '0123456789abcdef':
        if c*6 in key_hex:
            return True
    
    # 2. Простые последовательности
    simple_seqs = {
        '012345', '123456', '234567', '345678', '456789', '56789a',
        '6789ab', '789abc', '89abcd', '9abcde', 'abcdef',
        '543210', '654321', '765432', '876543', '987654', 'a98765',
        'ba9876', 'cba987', 'dcba98', 'edcba9', 'fedcba'
    }
    
    for seq in simple_seqs:
        if seq in key_hex:
            return True
    
    return False

def load_checkpoint() -> int:
    """Загрузка последней позиции из файла"""
    if not os.path.exists(CONFIG['CHECKPOINT_FILE']):
        return CONFIG['START_KEY']
    
    for _ in range(CONFIG['MAX_RETRIES']):
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
        except (json.JSONDecodeError, KeyError, FileNotFoundError) as e:
            print(f"{Colors.RED}Checkpoint error, attempt {_+1}/{CONFIG['MAX_RETRIES']}: {e}{Colors.END}")
            time.sleep(1)
    
    print(f"{Colors.RED}Fatal: Could not load checkpoint, resetting to start{Colors.END}")
    return CONFIG['START_KEY']

def atomic_save_checkpoint(current_key: int, stats):
    """Атомарное сохранение прогресса"""
    temp_file = f"{CONFIG['CHECKPOINT_FILE']}.{os.getpid()}.tmp"
    for _ in range(CONFIG['MAX_RETRIES']):
        try:
            with open(temp_file, 'w') as f:
                json.dump({
                    'last_key': hex(current_key),
                    'timestamp': time.time(),
                    'stats': {
                        'keys_checked': stats['keys_checked'],
                        'keys_found': stats['keys_found'],
                        'keys_skipped': stats['keys_skipped']
                    }
                }, f, indent=2)
            
            os.replace(temp_file, CONFIG['CHECKPOINT_FILE'])
            return
        except Exception as e:
            print(f"{Colors.RED}Error saving checkpoint (attempt {_+1}): {e}{Colors.END}")
            time.sleep(1)
    
    print(f"{Colors.RED}Fatal: Could not save checkpoint{Colors.END}")

def private_to_address(private_key_hex: str) -> Optional[str]:
    """Конвертация приватного ключа в Bitcoin-адрес"""
    try:
        if len(private_key_hex) != 64:
            return None
            
        priv = bytes.fromhex(private_key_hex)
        pub_key = coincurve.PublicKey.from_valid_secret(priv).format(compressed=True)
        
        sha256_hash = hashlib.sha256(pub_key).digest()
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_hash)
        
        versioned_payload = b'\x00' + ripemd160.digest()
        checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]
        
        return base58.b58encode(versioned_payload + checksum).decode('utf-8')
    except Exception as e:
        print(f"{Colors.RED}Error converting key {private_key_hex}: {e}{Colors.END}")
        return None

def process_key_batch(start_key: int, end_key: int, target: str):
    """Обработка диапазона ключей"""
    local_stats = {
        'keys_checked': 0,
        'keys_skipped': 0,
        'keys_found': 0
    }
    found_key = None
    
    for k in range(start_key, end_key + 1):
        private_key = f"{k:064x}"
        
        if is_junk_key(private_key):
            local_stats['keys_skipped'] += 1
            continue
            
        address = private_to_address(private_key)
        local_stats['keys_checked'] += 1
        
        if address == target:
            print(f"\n{Colors.GREEN}POTENTIAL MATCH FOUND!{Colors.END}")
            print(f"Private key: {private_key}")
            print(f"Calculated address: {address}")
            print(f"Target address: {target}")
            local_stats['keys_found'] += 1
            found_key = private_key
            break
    
    return local_stats, found_key

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
        elapsed = time.time() - self.start_time
        keys_per_sec = stats['keys_checked'] / elapsed if elapsed > 0 else 0
        
        print(
            f"{Colors.YELLOW}[Status] Keys: {stats['keys_checked']:,} | "
            f"Skipped: {stats['keys_skipped']:,} | "
            f"Speed: {self.format_speed(keys_per_sec)} | "
            f"Current: {hex(self.current_key)} | "
            f"Elapsed: {elapsed/3600:.2f} hours{Colors.END}"
        )

    def run(self):
        print(f"{Colors.YELLOW}Target address: {CONFIG['TARGET_ADDRESS']}{Colors.END}")
        print(f"Search range: {hex(CONFIG['START_KEY'])} - {hex(CONFIG['END_KEY'])}")
        print(f"Starting from: {hex(self.current_key)}")
        print(f"{Colors.BLUE}Filtering junk keys (sequences/repeats){Colors.END}")
        
        num_cores = max(1, multiprocessing.cpu_count())
        print(f"{Colors.BLUE}Using {num_cores} CPU cores{Colors.END}")
        
        manager = multiprocessing.Manager()
        shared_stats = manager.dict({
            'keys_checked': 0,
            'keys_found': 0,
            'keys_skipped': 0
        })
        stats_lock = manager.Lock()
        
        pool = multiprocessing.Pool(
            processes=num_cores,
            initializer=init_shared_stats,
            initargs=(shared_stats, stats_lock)
        )
        
        last_status_time = time.time()
        last_save_time = time.time()
        found_key = None

        try:
            while self.current_key <= CONFIG['END_KEY'] and not found_key and not self.should_stop:
                # Динамический размер батча
                batch_size = CONFIG['BATCH_PER_CORE'] * num_cores
                batch_end = min(self.current_key + batch_size - 1, CONFIG['END_KEY'])
                
                # Создаем задачи для каждого ядра
                tasks = []
                keys_per_core = max(1, (batch_end - self.current_key + 1) // num_cores)
                
                for i in range(num_cores):
                    start = self.current_key + i * keys_per_core
                    end = start + keys_per_core - 1 if i < num_cores - 1 else batch_end
                    if start > end:
                        continue
                    tasks.append((start, end, CONFIG['TARGET_ADDRESS']))
                
                # Параллельная обработка
                results = pool.starmap(process_key_batch, tasks)
                
                # Обработка результатов
                for local_stats, result in results:
                    with stats_lock:
                        shared_stats['keys_checked'] += local_stats['keys_checked']
                        shared_stats['keys_skipped'] += local_stats['keys_skipped']
                        shared_stats['keys_found'] += local_stats['keys_found']
                    
                    if result:
                        found_key = result
                        break
                
                self.current_key = batch_end + 1
                
                # Периодическое сохранение и вывод статистики
                current_time = time.time()
                if current_time - last_status_time >= CONFIG['STATUS_INTERVAL']:
                    self.print_status(shared_stats)
                    last_status_time = current_time
                
                if current_time - last_save_time >= 300:  # Сохраняем каждые 5 минут
                    atomic_save_checkpoint(self.current_key - 1, shared_stats)
                    last_save_time = current_time
            
            # Обработка результатов поиска
            if found_key:
                print(f"\n{Colors.GREEN}SUCCESS: Key found!{Colors.END}")
                print(f"Private key: {found_key}")
                with open(CONFIG['FOUND_KEYS_FILE'], 'a') as f:
                    f.write(f"{time.ctime()}\n")
                    f.write(f"Private: {found_key}\n")
                    f.write(f"Address: {CONFIG['TARGET_ADDRESS']}\n\n")
            elif self.should_stop:
                print(f"\n{Colors.YELLOW}SEARCH STOPPED BY USER{Colors.END}")
            else:
                print(f"\n{Colors.BLUE}SEARCH COMPLETED{Colors.END}")
                print(f"{Colors.YELLOW}Target key not found in specified range{Colors.END}")
                
        except Exception as e:
            print(f"\n{Colors.RED}Critical error: {e}{Colors.END}")
            raise
        finally:
            pool.close()
            pool.join()
            atomic_save_checkpoint(self.current_key - 1, shared_stats)
            
            # Финальная статистика
            elapsed = time.time() - self.start_time
            total_checked = shared_stats['keys_checked']
            keys_per_sec = total_checked / elapsed if elapsed > 0 else 0
            
            print(f"\n{Colors.BLUE}=== FINAL STATS ===")
            print(f"Total keys checked: {total_checked:,}")
            print(f"Total keys skipped: {shared_stats['keys_skipped']:,}")
            print(f"Total time: {elapsed/3600:.2f} hours")
            print(f"Average speed: {self.format_speed(keys_per_sec)}")
            print(f"Last checked key: {hex(self.current_key)}")
            print(f"=================={Colors.END}")

    def format_speed(self, speed: float) -> str:
        if speed >= 1_000_000:
            return f"{speed/1_000_000:.2f} M keys/sec"
        elif speed >= 1_000:
            return f"{speed/1_000:.1f} K keys/sec"
        return f"{speed:,.0f} keys/sec"

if __name__ == "__main__":
    multiprocessing.freeze_support()
    searcher = KeySearcher()
    searcher.run()
