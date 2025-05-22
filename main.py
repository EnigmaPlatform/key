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
    TARGET = bytes.fromhex("f6f5431d25bbf7b12e8add9af5e3475c44a0a5b8")
    START = 0x60102a304e0c796a80
    END = 0x7fffffffffffffffff
    BATCH = 5_000_000
    UPDATE = 1_000_000

@lru_cache(maxsize=1<<20)
def is_trivial(key_hex: str) -> bool:
    part = key_hex[-16:]
    if len(set(part)) < 4:
        return True
    for i in range(len(part)-3):
        if (ord(part[i+1]) - ord(part[i]) == 1 and \
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

def worker(start, end, target, result, last_key):
    found = None
    for key_int in range(start, end+1):
        key_hex = f"{key_int:064x}"
        if not is_trivial(key_hex[-16:]) and key_to_hash(key_hex) == target:
            found = key_hex
            break
    last_key.value = end  # Сохраняем последний проверенный ключ
    if found:
        result['found'] = found

class Solver:
    def __init__(self):
        self.current = Config.START
        self.stats = {'checked': 0, 'speed': 0}
        self.start_time = time.time()
        self.last_key = multiprocessing.Value('Q', Config.START)
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
              f"ETA: {remaining/3600:.1f}h | Last: {hex(self.last_key.value)}", end='', flush=True)

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
                
                for i in range(multiprocessing.cpu_count()):
                    start = self.current + i*(batch_end-self.current)//multiprocessing.cpu_count()
                    end = start + (batch_end-self.current)//multiprocessing.cpu_count() - 1
                    if i == multiprocessing.cpu_count()-1:
                        end = batch_end
                    tasks.append((start, end, Config.TARGET, result, self.last_key))
                
                pool.starmap(worker, tasks)
                
                self.stats['checked'] += batch_end - self.current + 1
                self.current = batch_end + 1
                self.status()
                
                if 'found' in result:
                    self.found(result['found'])
                    return
        
        print("\nScan completed - nothing found")
        print(f"Last checked key: {hex(self.last_key.value)}")

    def found(self, key):
        print(f"\n\n!!! FOUND PRIVATE KEY !!!\n{key}")
        with open(Config.FOUND_FILE, 'a') as f:
            f.write(f"{time.ctime()}\n{key}\n")

if __name__ == "__main__":
    if os.name == 'posix':
        multiprocessing.set_start_method('fork')
    Solver().run()
