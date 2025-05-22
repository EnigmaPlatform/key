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
    'FOUND_KEYS_FILE': "found_keys.txt",
    'STATUS_INTERVAL': 60,  # Выводить статус каждые 60 секунд
    'TARGET_RIPEMD': bytes.fromhex("f6f5431d25bbf7b12e8add9af5e3475c44a0a5b8"),
    'START_KEY': 0x60102a304e0c796a80,
    'END_KEY': 0x7fffffffffffffffff,
    'BATCH_PER_CORE': 5_000_000,
    'MAX_RETRIES': 3,
    'MIN_ENTROPY': 3.0,
    'PRIORITY_RANGE_PERCENT': 15,
    'HASH_TEST_ITERATIONS': 1_000_000
}

# [Остальные функции остаются без изменений...]

class KeySearcher:
    def __init__(self):
        self.current_key = CONFIG['START_KEY']
        self.should_stop = False
        self.start_time = time.time()
        signal.signal(signal.SIGINT, self.handle_interrupt)
        signal.signal(signal.SIGTERM, self.handle_interrupt)
        self.last_status_time = time.time()  # Добавляем переменную для отслеживания времени последнего статуса

    def handle_interrupt(self, signum, frame):
        print(f"\n{Colors.YELLOW}Received interrupt signal, stopping...{Colors.END}")
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
        self.last_status_time = time.time()  # Обновляем время последнего статуса

    # [Остальные методы класса остаются без изменений...]

    def run(self):
        """Основной цикл поиска ключей."""
        print(f"{Colors.BLUE}=== Bitcoin Puzzle Solver ==={Colors.END}")
        print(f"Target: {Colors.YELLOW}{CONFIG['TARGET_RIPEMD'].hex()}{Colors.END}")
        print(f"Range: {Colors.YELLOW}{hex(CONFIG['START_KEY'])} - {hex(CONFIG['END_KEY'])}{Colors.END}")
        print(f"Priority search: top {CONFIG['PRIORITY_RANGE_PERCENT']}% of range")
        print(f"Filters: entropy > {CONFIG['MIN_ENTROPY']}, pattern checks, checksum validation")
        
        # Запуск теста производительности
        perform_hash_test()
        
        num_cores = multiprocessing.cpu_count()
        processes_per_core = 2
        total_processes = num_cores * processes_per_core
        print(f"Using {total_processes} processes ({num_cores} cores × {processes_per_core} processes per core)")
        
        manager = multiprocessing.Manager()
        shared_stats = manager.dict({
            'keys_checked': 0,
            'keys_found': 0,
            'keys_skipped': 0
        })
        
        pool = multiprocessing.Pool(processes=total_processes, initializer=init_shared_stats, initargs=(shared_stats,))
        found_key = None
        
        try:
            while self.current_key <= CONFIG['END_KEY'] and not found_key and not self.should_stop:
                # Выводим статус, если прошло достаточно времени
                if time.time() - self.last_status_time >= CONFIG['STATUS_INTERVAL']:
                    self.print_status(shared_stats)
                
                current_percent = (self.current_key - CONFIG['START_KEY']) / (CONFIG['END_KEY'] - CONFIG['START_KEY'])
                if current_percent > 0.85:
                    batch_size = CONFIG['BATCH_PER_CORE'] * num_cores
                else:
                    batch_size = CONFIG['BATCH_PER_CORE'] * num_cores * 4
                
                batch_end = min(self.current_key + batch_size - 1, CONFIG['END_KEY'])
                
                keys_per_process = (batch_end - self.current_key + 1) // total_processes
                tasks = []
                for i in range(total_processes):
                    start = self.current_key + i * keys_per_process
                    end = start + keys_per_process - 1 if i < total_processes - 1 else batch_end
                    tasks.append((start, end, CONFIG['TARGET_RIPEMD'], shared_stats))
                
                results = pool.starmap(process_key_batch, tasks)
                
                for result in results:
                    if result:
                        found_key = result
                        break
                
                self.current_key = batch_end + 1
            
            # Выводим финальный статус
            self.print_status(shared_stats)
            
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
