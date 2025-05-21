import hashlib
import base58
import time
import json
import os
import multiprocessing
import coincurve
import signal
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
    'SAVE_INTERVAL': 10_000_000,
    'STATUS_INTERVAL': 300,
    'TARGET_ADDRESS': "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU",
    'START_KEY': 0x600000000000000000,
    'END_KEY': 0x7fffffffffffffffff,
    'BATCH_PER_CORE': 5_000_000
}

def load_checkpoint() -> int:
    """Загружает последний проверенный ключ с проверкой диапазона"""
    if not os.path.exists(CONFIG['CHECKPOINT_FILE']):
        return CONFIG['START_KEY']
    
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
            
    except Exception as e:
        print(f"{Colors.RED}Error loading checkpoint: {e}{Colors.END}")
        return CONFIG['START_KEY']

def save_checkpoint(current_key: int):
    """Сохраняет текущую позицию с обработкой ошибок"""
    try:
        with open(CONFIG['CHECKPOINT_FILE'] + '.tmp', 'w') as f:
            json.dump({'last_key': hex(current_key)}, f)
        os.replace(CONFIG['CHECKPOINT_FILE'] + '.tmp', CONFIG['CHECKPOINT_FILE'])
    except Exception as e:
        print(f"{Colors.RED}Error saving checkpoint: {e}{Colors.END}")

@lru_cache(maxsize=2_000_000)
def private_to_address(private_key_hex: str) -> Optional[str]:
    """Конвертирует приватный ключ в адрес"""
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
    """Обрабатывает диапазон ключей в процессе"""
    try:
        for k in key_range:
            private_key = f"{k:064x}"
            if private_to_address(private_key) == target:
                result_queue.put(private_key)
                return
        result_queue.put(None)
    except Exception as e:
        print(f"{Colors.RED}Process error: {e}{Colors.END}")
        result_queue.put(None)

def format_speed(speed: float) -> str:
    """Форматирует скорость поиска"""
    if speed >= 1_000_000:
        return f"{speed/1_000_000:.2f} M keys/sec"
    return f"{speed:,.0f} keys/sec"

class KeySearcher:
    def __init__(self):
        self.current_key = load_checkpoint()
        self.should_stop = False
        signal.signal(signal.SIGINT, self.handle_interrupt)
        signal.signal(signal.SIGTERM, self.handle_interrupt)

    def handle_interrupt(self, signum, frame):
        """Обрабатывает прерывание"""
        print(f"\n{Colors.YELLOW}Received interrupt signal, saving progress...{Colors.END}")
        self.should_stop = True

    def run(self):
        print(f"{Colors.YELLOW}Target address: {CONFIG['TARGET_ADDRESS']}{Colors.END}")
        print(f"Search range: {hex(CONFIG['START_KEY'])} - {hex(CONFIG['END_KEY'])}")
        
        if self.current_key > CONFIG['START_KEY']:
            print(f"{Colors.BLUE}Resuming from checkpoint: {hex(self.current_key)}{Colors.END}")
        
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
            while self.current_key <= CONFIG['END_KEY'] and not found_key and not self.should_stop:
                batch_end = min(self.current_key + batch_size - 1, CONFIG['END_KEY'])
                
                # Разделяем работу между ядрами
                ranges = []
                keys_per_core = (batch_end - self.current_key + 1) // num_cores
                for i in range(num_cores):
                    start = self.current_key + i * keys_per_core
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
                
                # Ожидаем завершения
                for _ in range(num_cores):
                    if key := result_queue.get():
                        found_key = key
                        break
                
                # Останавливаем если нашли ключ или получили прерывание
                if found_key or self.should_stop:
                    for p in processes:
                        p.terminate()
                    break
                
                # Обновляем статистику
                total_checked += batch_end - self.current_key + 1
                self.current_key = batch_end + 1
                
                # Сохраняем прогресс
                if total_checked % CONFIG['SAVE_INTERVAL'] == 0:
                    save_checkpoint(self.current_key - 1)
                
                # Выводим статус
                if time.time() - last_status_time >= CONFIG['STATUS_INTERVAL']:
                    elapsed = time.time() - start_time
                    keys_per_sec = total_checked / elapsed
                    print(
                        f"{Colors.YELLOW}[Status] Keys: {total_checked:,} | "
                        f"Speed: {format_speed(keys_per_sec)} | "
                        f"Current: {hex(self.current_key)} | "
                        f"Elapsed: {elapsed/60:.1f} min{Colors.END}"
                    )
                    last_status_time = time.time()
            
            # Финализация
            if found_key:
                print(f"\n{Colors.GREEN}SUCCESS: Key found!{Colors.END}")
                print(f"Private key: {found_key}")
                with open(CONFIG['FOUND_KEYS_FILE'], 'a') as f:
                    f.write(f"{time.ctime()}\n")
                    f.write(f"Private: {found_key}\n")
                    f.write(f"Address: {CONFIG['TARGET_ADDRESS']}\n\n")
            elif self.should_stop:
                print(f"\n{Colors.YELLOW}SEARCH STOPPED{Colors.END}")
            else:
                print(f"\n{Colors.BLUE}SEARCH COMPLETED{Colors.END}")
                print(f"{Colors.YELLOW}Target key not found in specified range{Colors.END}")
                
        except Exception as e:
            print(f"\n{Colors.RED}Error: {e}{Colors.END}")
        finally:
            for p in processes:
                if p.is_alive():
                    p.terminate()
            
            # Гарантированное сохранение прогресса
            if not found_key and self.current_key > CONFIG['START_KEY']:
                save_checkpoint(self.current_key - 1)
            
            elapsed = time.time() - start_time
            keys_per_sec = total_checked / elapsed if elapsed > 0 else 0
            print(f"\n{Colors.BLUE}=== FINAL STATS ===")
            print(f"Total keys checked: {total_checked:,}")
            print(f"Total time: {elapsed/60:.1f} minutes")
            print(f"Average speed: {format_speed(keys_per_sec)}")
            print(f"Last checked key: {hex(self.current_key)}")
            print(f"=================={Colors.END}")

if __name__ == "__main__":
    multiprocessing.freeze_support()
    searcher = KeySearcher()
    searcher.run()
