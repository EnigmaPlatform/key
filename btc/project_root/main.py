from concurrent.futures import ProcessPoolExecutor
import threading
import time
import os
import secrets
import gc
from btc_cracker.core import process_range
from btc_cracker.utils import logger, print_progress_bar
from btc_cracker.config import CONFIG

class BlockCounter:
    def __init__(self):
        self.count = 0
        self.lock = threading.Lock()
    
    def increment(self):
        with self.lock:
            self.count += 1
    
    def get_count(self):
        with self.lock:
            return self.count

block_counter = BlockCounter()

def monitor_progress(total_keys: int, num_threads: int):
    """Мониторинг прогресса"""
    stats = {i: {'current': 0, 'start': 0, 'end': 0} for i in range(num_threads)}
    start_time = time.time()
    found = False
    
    try:
        while not found:
            total_checked = 0
            any_active = False
            
            for thread_id in range(num_threads):
                progress_file = os.path.join("progress_states", f"thread_{thread_id}.progress")
                
                try:
                    with open(progress_file, 'r') as f:
                        for line in f:
                            parts = line.strip().split()
                            if parts[0] == "FOUND":
                                logger.log(f"\n{Fore.GREEN}Найден ключ: 0x{parts[1]}{Style.RESET_ALL}")
                                found = True
                                break
                            elif parts[0] == "START":
                                stats[thread_id]['start'] = int(parts[1])
                                stats[thread_id]['end'] = int(parts[2])
                            elif parts[0] == "PROGRESS":
                                stats[thread_id]['current'] = int(parts[1])
                                any_active = True
                except FileNotFoundError:
                    continue
                
                if found:
                    break
            
            if any_active:
                total_range = sum(s['end'] - s['start'] for s in stats.values())
                completed = sum(s['current'] - s['start'] for s in stats.values())
                speed = completed / (time.time() - start_time)
                
                mem = psutil.virtual_memory()
                cpu = psutil.cpu_percent()
                
                os.system('cls' if os.name == 'nt' else 'clear')
                logger.log(f"{Fore.CYAN}=== ПРОГРЕСС ПОИСКА ===")
                logger.log(print_progress_bar(completed, total_range))
                logger.log(f"Скорость: {speed:,.0f} ключ/сек")
                logger.log(f"Блоков: {block_counter.get_count()}")
                logger.log(f"Память: {mem.percent}%")
                logger.log(f"CPU: {cpu:.1f}%")
            
            time.sleep(1)
    except KeyboardInterrupt:
        pass

def main():
    if os.path.exists("progress_states"):
        import shutil
        shutil.rmtree("progress_states")
    
    gc.disable()
    
    monitor_thread = threading.Thread(
        target=monitor_progress,
        args=(CONFIG['check_range'], CONFIG['num_threads']),
        daemon=True
    )
    monitor_thread.start()
    
    try:
        with ProcessPoolExecutor(max_workers=CONFIG['num_threads']) as executor:
            while True:
                start_key = secrets.randbelow(CONFIG['end_range'] - CONFIG['start_range']) + CONFIG['start_range']
                block_counter.increment()
                
                futures = []
                for i in range(CONFIG['num_threads']):
                    chunk_start = start_key + i * CONFIG['chunk_size']
                    chunk_end = chunk_start + CONFIG['chunk_size']
                    futures.append(executor.submit(process_range, chunk_start, chunk_end, i))
                
                for future in futures:
                    future.result()
                
                for i in range(CONFIG['num_threads']):
                    try:
                        os.remove(f"progress_states/thread_{i}.progress")
                    except:
                        pass
                
                time.sleep(0.5)
    except KeyboardInterrupt:
        logger.log(f"\n{Fore.YELLOW}Поиск остановлен{Style.RESET_ALL}")
    finally:
        gc.enable()

if __name__ == "__main__":
    main()
