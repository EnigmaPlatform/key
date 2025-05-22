import hashlib
import time
import os
import multiprocessing
import coincurve
import signal
import math
from collections import Counter
from functools import lru_cache

# Конфигурация
class Config:
    FOUND_FILE = "found.txt"
    TARGET = bytes.fromhex("5db8cda53a6a002db10365967d7f85d19e171b10")  # Замените на нужный хеш
    START = 0x349b84b643115c4ef1 # Начальный ключ (рекомендуемый для Puzzle)
    END = 0x349b84b6431a6c4ef1   # Конечный ключ
    BATCH = 2_000           # Размер батча на ядро
    UPDATE = 1_000_000          # Обновление статуса

# Быстрые проверки ключей
@lru_cache(maxsize=1<<20)
def is_trivial(key_hex: str) -> bool:
    part = key_hex[-16:]
    # Проверка повторяющихся символов
    if len(set(part)) < 4:
        return True
    # Проверка последовательностей
    for i in range(len(part)-3):
        if (ord(part[i+1]) - ord(part[i]) == 1 and
           ord(part[i+2]) - ord(part[i+1]) == 1 and
           ord(part[i+3]) - ord(part[i+2]) == 1):
            return True
    return False

# Оптимизированное хеширование
def key_to_hash(key_hex: str) -> bytes:
    try:
        priv = bytes.fromhex(key_hex)
        pub = coincurve.PublicKey.from_secret(priv).format(compressed=True)
        return hashlib.new('ripemd160', hashlib.sha256(pub).digest()).digest()
    except:
        return b''

# Рабочая функция для процессов
def worker(start, end, target, result):
    found = None
    for key_int in range(start, end+1):
        key_hex = f"{key_int:064x}"
        if not is_trivial(key_hex[-16:]) and key_to_hash(key_hex) == target:
            found = key_hex
            break
    if found:
        result['found'] = found

class Solver:
    def __init__(self):
        self.current = Config.START
        self.stats = {'checked': 0, 'speed': 0}
        self.start_time = time.time()
        signal.signal(signal.SIGINT, self.stop)

    def stop(self, *args):
        print("\nStopping...")
        self.should_stop = True

    def status(self):
        elapsed = time.time() - self.start_time
        self.stats['speed'] = self.stats['checked'] / max(elapsed, 1)
        remaining = (Config.END - self.current) / max(self.stats['speed'], 1)
        print(f"\rChecked: {self.stats['checked']:,} | Speed: {self.stats['speed']/1e6:.2f}M/s | "
              f"Progress: {(self.current-Config.START)/(Config.END-Config.START)*100:.2f}% | "
              f"ETA: {remaining/3600:.1f}h", end='')

    def run(self):
        print(f"Starting scan from {hex(Config.START)} to {hex(Config.END)}")
        print(f"Using {multiprocessing.cpu_count()} cores")
        
        manager = multiprocessing.Manager()
        result = manager.dict()
        self.should_stop = False
        
        with multiprocessing.Pool() as pool:
            while self.current <= Config.END and not self.should_stop:
                tasks = []
                batch_size = Config.BATCH * multiprocessing.cpu_count()
                batch_end = min(self.current + batch_size, Config.END)
                
                # Распределение задач
                for i in range(multiprocessing.cpu_count()):
                    start = self.current + i*(batch_end-self.current)//multiprocessing.cpu_count()
                    end = start + (batch_end-self.current)//multiprocessing.cpu_count() - 1
                    if i == multiprocessing.cpu_count()-1:
                        end = batch_end
                    tasks.append((start, end, Config.TARGET, result))
                
                # Параллельное выполнение
                pool.starmap(worker, tasks)
                
                # Обновление статуса
                self.stats['checked'] += batch_end - self.current + 1
                self.current = batch_end + 1
                self.status()
                
                if 'found' in result:
                    self.found(result['found'])
                    return
        
        print("\nScan completed - nothing found")

    def found(self, key):
        print(f"\n\n!!! FOUND PRIVATE KEY !!!\n{key}")
        with open(Config.FOUND_FILE, 'a') as f:
            f.write(f"{time.ctime()}\n{key}\n")

if __name__ == "__main__":
    if os.name == 'posix':
        multiprocessing.set_start_method('fork')
    Solver().run()
