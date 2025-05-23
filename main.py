import hashlib
import time
import os
import multiprocessing
import coincurve
import signal
import sys
from functools import lru_cache

class Config:
    FOUND_FILE = "found.txt"
    TARGET = None  # Will be set in __init__
    START = 0x349b84b643113c4ef1
    END = 0x349b84b6431a6c4ef1
    BATCH = 50_000
    STATS_INTERVAL = 1_000_000
    PROGRESS_INTERVAL = 10

def address_to_hash(address: str) -> bytes:
    """Convert Bitcoin address to RIPEMD-160 hash"""
    from base58 import b58decode_check
    return b58decode_check(address)[1:]

@lru_cache(maxsize=1<<20)
def is_trivial(key_hex: str) -> bool:
    part = key_hex[-16:]
    if len(set(part)) < 4:
        return True
    for i in range(len(part)-3):
        if (ord(part[i+1]) - ord(part[i]) == 1 and 
            ord(part[i+2]) - ord(part[i+1]) == 1 and 
            ord(part[i+3]) - ord(part[i+2]) == 1):
            return True
    return False

def key_to_hash(key_hex: str) -> bytes:
    try:
        priv = bytes.fromhex(key_hex)
        pub = coincurve.PublicKey.from_secret(priv).format(compressed=True)
        return hashlib.new('ripemd160', hashlib.sha256(pub).digest()).digest()
    except Exception:
        return b''

def worker(args):
    start, end, target = args
    found = None
    last_checked = start
    processed = 0
    for key_int in range(start, end + 1):
        key_hex = f"{key_int:064x}"
        last_checked = key_int
        processed += 1
        if not is_trivial(key_hex[-16:]):
            if key_to_hash(key_hex) == target:
                found = key_hex
                break
    return {'found': found, 'last': last_checked, 'processed': processed}

class Solver:
    def __init__(self, target_address=None):
        self.current = Config.START
        self.stats = {
            'checked': 0,
            'total_checked': 0,
            'speed': 0,
            'last_speed_time': time.time(),
            'last_speed_count': 0
        }
        self.start_time = time.time()
        self.last_checked = Config.START
        self.last_print_time = time.time()
        signal.signal(signal.SIGINT, self.stop)
        self.should_stop = False
        
        # Set target hash
        if target_address:
            Config.TARGET = address_to_hash(target_address)
        else:
            Config.TARGET = bytes.fromhex("5db8cda53a6a002db10365967d7f85d19e171b10")

    def stop(self, *args):
        print("\nStopping...")
        self.should_stop = True

    def print_progress(self, force_print=False):
        now = time.time()
        elapsed = now - self.start_time
        time_since_last_print = now - self.last_print_time
        
        if now - self.stats['last_speed_time'] >= 5:
            self.stats['speed'] = (self.stats['total_checked'] - self.stats['last_speed_count']) / \
                                 (now - self.stats['last_speed_time'])
            self.stats['last_speed_time'] = now
            self.stats['last_speed_count'] = self.stats['total_checked']
        
        if force_print or time_since_last_print >= Config.PROGRESS_INTERVAL or \
           self.stats['total_checked'] // Config.STATS_INTERVAL != \
           (self.stats['total_checked'] - self.stats['checked']) // Config.STATS_INTERVAL:
            
            remaining = max(0, (Config.END - self.current) / max(self.stats['speed'], 1e-9))
            
            print(f"\n[Progress] Checked: {self.stats['total_checked']:,} | "
                  f"Speed: {self.stats['speed']/1e6:.2f} Mkeys/sec | "
                  f"Progress: {(self.current-Config.START)/(Config.END-Config.START)*100:.2f}% | "
                  f"Last key: {hex(self.last_checked)} | "
                  f"ETA: {remaining/3600:.1f} hours")
            
            self.last_print_time = now

    def run(self):
        print(f"Starting scan from {hex(Config.START)} to {hex(Config.END)}")
        print(f"Target hash: {Config.TARGET.hex()}")
        print(f"Using cores: {multiprocessing.cpu_count()}")
        
        with multiprocessing.Pool() as pool:
            while self.current <= Config.END and not self.should_stop:
                tasks = []
                batch_size = min(Config.BATCH * multiprocessing.cpu_count(), Config.END - self.current + 1)
                batch_end = self.current + batch_size - 1
                
                for i in range(multiprocessing.cpu_count()):
                    start = self.current + i * (batch_size // multiprocessing.cpu_count())
                    end = start + (batch_size // multiprocessing.cpu_count()) - 1
                    if i == multiprocessing.cpu_count() - 1:
                        end = batch_end
                    tasks.append((start, end, Config.TARGET))
                
                results = pool.map(worker, tasks)
                
                for result in results:
                    if result['found']:
                        self.found(result['found'])
                        return
                    self.last_checked = max(self.last_checked, result['last'])
                    self.stats['checked'] = result['processed']
                    self.stats['total_checked'] += result['processed']
                
                self.current = batch_end + 1
                self.print_progress()
        
        self.print_progress(force_print=True)
        print("\nScan completed - key not found")

    def found(self, key):
        print(f"\n\n!!! KEY FOUND !!!")
        print(f"Private key: {key}")
        print(f"Hash: {key_to_hash(key).hex()}")
        
        with open(Config.FOUND_FILE, 'a') as f:
            f.write(f"{time.ctime()}\n{key}\n")

if __name__ == "__main__":
    if os.name == 'posix':
        multiprocessing.set_start_method('fork')
    
    target_address = sys.argv[1] if len(sys.argv) > 1 else None
    Solver(target_address).run()
