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
    TARGET = bytes.fromhex("5db8cda53a6a002db10365967d7f85d19e171b10")  # Замените на нужный хеш
    START = 0x349b84b6431a6c4ef1  # Начальный ключ
    END = 0x349b84b6431a5c4ef1    # Конечный ключ
    BATCH = 5_000             # Размер батча на ядро
    UPDATE = 1_000_000            # Частота обновления статуса

@lru_cache(maxsize=1<<20)
def is_trivial(key_hex: str) -> bool:
    part = key_hex[-16:]
    if len(set(part)) < 4:
        return True
    for i in range(len(part)-3):
        if (ord(part[i+1]) - ord(part[i])) == 1 and \
           ord(part[i+2]) - ord(part[i+1]) == 1 and \
           ord(part[i+3]) - ord(part[i+2]) == 1:
            return True
    return False

def key_to_hash(key_hex: str) -> bytes:
    try:
        priv = bytes.fromhex(key_hex)
        pub = coincurve.PublicKey.from_secret(priv).format(compressed=True)
        return hashlib.new('ripemd160', hashlib.sha256(pub).digest())
    except:
        return b''

def worker(start, end, target, result, last_checked):
    found = None
    for key_int in range(start, end+1):
        key_hex = f"{key_int:064x}"
        if not is_trivial(key_hex[-16:]) and key_to_hash(key_hex) == target:
            found = key_hex
            break
    # Обновляем последний проверенный ключ
    with last_checked.get_lock():
        last_checked.value = max(last_checked.value, end)
    if found:
        result['found'] = found

class Solver:
    def __init__(self):
        self.current = Config.START
        self.stats = {'checked': 0, 'speed': 0}
        self.start_time = time.time()
        self.last_checked = multiprocessing.Value('Q', Config.START)
        signal.signal(signal.SIGINT, self.stop)

    def stop(self, *args):
        print("\nStopping...")
        self.should_stop = True

    def status(self):
        elapsed = time.time() - self.start_time
        self.stats['speed'] = self.stats['checked'] / max(elapsed, 1)
        remaining = (Config.END - self.current) / max(self.stats['speed'], 1)
        
        # Получаем последний проверенный ключ
        with self.last_checked.get_lock():
            last_key = self.last_checked.value
        
        print(f"\n=== Статистика ===")
        print(f"Проверено ключей: {self.stats['checked']:,}")
        print(f"Скорость: {self.stats['speed']/1e6:.2f} млн/сек")
        print(f"Прогресс: {(self.current-Config.START)/(Config.END-Config.START)*100:.2f}%")
        print(f"Последний ключ: {hex(last_key)}")
        print(f"Завершение через: {remaining/3600:.1f} часов")
        print(f"==================")

    def run(self):
        print(f"Начало сканирования от {hex(Config.START)} до {hex(Config.END)}")
        print(f"Используется ядер: {multiprocessing.cpu_count()}")
        
        manager = multiprocessing.Manager()
        result = manager.dict()
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
                    tasks.append((start, end, Config.TARGET, result, self.last_checked))
                
                pool.starmap(worker, tasks)
                
                self.stats['checked'] += batch_end - self.current + 1
                self.current = batch_end + 1
                
                # Выводим статус каждые UPDATE ключей или каждые 60 секунд
                if (self.stats['checked'] % Config.UPDATE == 0 or 
                    time.time() - last_status_time > 60):
                    self.status()
                    last_status_time = time.time()
                
                if 'found' in result:
                    self.found(result['found'])
                    return
        
        self.status()
        print("\nСканирование завершено - ключ не найден")

    def found(self, key):
        print(f"\n\n!!! КЛЮЧ НАЙДЕН !!!")
        print(f"Приватный ключ: {Colors.YELLOW}{key}{Colors.END}")
        print(f"Хеш: {key_to_hash(key).hex()}")
        
        with open(Config.FOUND_FILE, 'a') as f:
            f.write(f"{time.ctime()}\n{key}\n")

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'

if __name__ == "__main__":
    if os.name == 'posix':
        multiprocessing.set_start_method('fork')
    Solver().run()
