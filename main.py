import hashlib
import time
import os
import multiprocessing
import coincurve
import signal
import math
from collections import Counter
from functools import lru_cache

class Config:
    FOUND_FILE = "found.txt"
    TARGET = bytes.fromhex("5db8cda53a6a002db10365967d7f85d19e171b10")
    START = 0x349b84b6431a4c4ef1
    END = 0x349b84b6431a6c4ef1
    BATCH = 5_000
    UPDATE = 10_000

@lru_cache(maxsize=1<<20)
def is_trivial(key_hex: str) -> bool:
    part = key_hex[-16:]
    if len(set(part)) < 4:
        return True
    for i in range(len(part)-3):
        if (ord(part[i+1]) - ord(part[i]) == 1 and \
           ord(part[i+2]) - ord(part[i+1]) == 1 and \
           ord(part[i+3]) - ord(part[i+2])) == 1:
            return True
    return False

def key_to_hash(key_hex: str) -> bytes:
    try:
        priv = bytes.fromhex(key_hex)
        pub = coincurve.PublicKey.from_secret(priv).format(compressed=True)
        return hashlib.new('ripemd160', hashlib.sha256(pub).digest())
    except:
        return b''

def worker(args):
    start, end, target = args
    found = None
    last_checked = start
    for key_int in range(start, end+1):
        key_hex = f"{key_int:064x}"
        last_checked = key_int
        if not is_trivial(key_hex[-16:]) and key_to_hash(key_hex) == target:
            found = key_hex
            break
    return {'found': found, 'last': last_checked}

class Solver:
    def __init__(self):
        self.current = Config.START
        self.stats = {'checked': 0, 'speed': 0}
        self.start_time = time.time()
        self.last_checked = Config.START
        signal.signal(signal.SIGINT, self.stop)

    def stop(self, *args):
        print("\nStopping...")
        self.should_stop = True

    def status(self):
        elapsed = time.time() - self.start_time
        self.stats['speed'] = self.stats['checked'] / max(elapsed, 1)
        remaining = (Config.END - self.current) / max(self.stats['speed'], 1)
        
        print(f"\n=== Статистика ===")
        print(f"Проверено ключей: {self.stats['checked']:,}")
        print(f"Скорость: {self.stats['speed']/1e6:.2f} млн/сек")
        print(f"Прогресс: {(self.current-Config.START)/(Config.END-Config.START)*100:.2f}%")
        print(f"Последний ключ: {hex(self.last_checked)}")
        print(f"Завершение через: {remaining/3600:.1f} часов")
        print(f"==================")

    def run(self):
        print(f"Начало сканирования от {hex(Config.START)} до {hex(Config.END)}")
        print(f"Используется ядер: {multiprocessing.cpu_count()}")
        
        self.should_stop = False
        last_status_time = time.time()
        
        with multiprocessing.Pool() as pool:
            while self.current <= Config.END and not self.should_stop:
                tasks = []
                batch_size = Config.BATCH * multiprocessing.cpu_count()
                batch_end = min(self.current + batch_size, Config.END)
                
                for i in range(multiprocessing.cpu_count()):
                    start = self.current + i*(batch_end-self.current)//multiprocessing.cpu_count()
                    end = start + (batch_end-self.current)//multiprocessing.cpu_count() - 1
                    if i == multiprocessing.cpu_count()-1:
                        end = batch_end
                    tasks.append((start, end, Config.TARGET))
                
                results = pool.map(worker, tasks)
                
                for result in results:
                    if result['found']:
                        self.found(result['found'])
                        return
                    self.last_checked = max(self.last_checked, result['last'])
                
                self.stats['checked'] += batch_end - self.current + 1
                self.current = batch_end + 1
                
                if (self.stats['checked'] % Config.UPDATE == 0 or 
                    time.time() - last_status_time > 5):
                    self.status()
                    last_status_time = time.time()
        
        self.status()
        print("\nСканирование завершено - ключ не найден")

    def found(self, key):
        print(f"\n\n!!! КЛЮЧ НАЙДЕН !!!")
        print(f"Приватный ключ: {key}")
        print(f"Хеш: {key_to_hash(key).hex()}")
        
        with open(Config.FOUND_FILE, 'a') as f:
            f.write(f"{time.ctime()}\n{key}\n")

if __name__ == "__main__":
    if os.name == 'posix':
        multiprocessing.set_start_method('fork')
    Solver().run()
