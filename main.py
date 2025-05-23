import hashlib
import time
import os
import multiprocessing
import coincurve
import signal
import sys
from functools import lru_cache
from numba import jit
import numpy as np

class Config:
    FOUND_FILE = "found.txt"
    TARGET = None  # Will be set in __init__
    START = 0x349b84b643113c4ef1
    END = 0x349b84b6431a6c4ef1
    BATCH = 50_000
    STATS_INTERVAL = 1_000_000  # Increased for better performance tracking
    PROGRESS_INTERVAL = 10
    FILTER_TRIVIAL = True  # Enable/disable trivial key filtering
    USE_NUMBA = True  # Enable/disable Numba acceleration

def address_to_hash(address: str) -> bytes:
    """Convert Bitcoin address to RIPEMD-160 hash"""
    from base58 import b58decode_check
    return b58decode_check(address)[1:]

@lru_cache(maxsize=1<<20)
def is_trivial(key_hex: str) -> bool:
    """Improved trivial key detection with more patterns"""
    part = key_hex[-16:]
    
    # Check for low character diversity
    if len(set(part)) < 4:
        return True
    
    # Check for sequential patterns (like 1234, abcd)
    for i in range(len(part)-3):
        if (ord(part[i+1]) - ord(part[i]) == 1 and 
            ord(part[i+2]) - ord(part[i+1]) == 1 and 
            ord(part[i+3]) - ord(part[i+2]) == 1):
            return True
    
    # Check for repeated patterns (like 0101, abab)
    if len(part) >= 4 and part[0] == part[2] and part[1] == part[3]:
        return True
    
    # Check for common weak patterns found in winning keys
    if part.endswith(('0', '2', '4', '6', '8', 'a', 'c', 'e')):
        return True
        
    return False

@jit(nopython=True)
def numba_is_potential(key_int: int) -> bool:
    """Numba-accelerated potential key check"""
    # Convert to hex string manually for Numba compatibility
    hex_chars = "0123456789abcdef"
    key_hex = ""
    for _ in range(16):
        key_hex = hex_chars[key_int & 0xf] + key_hex
        key_int >>= 4
    
    # Simple checks that Numba can handle
    # 1. Check last character is odd
    last_char = key_hex[-1]
    if last_char in ('0', '2', '4', '6', '8', 'a', 'c', 'e'):
        return False
    
    # 2. Check for sequential patterns
    for i in range(13):
        if (ord(key_hex[i+1]) - ord(key_hex[i]) == 1 and
            ord(key_hex[i+2]) - ord(key_hex[i+1]) == 1 and
            ord(key_hex[i+3]) - ord(key_hex[i+2]) == 1):
            return False
    
    return True

def key_to_hash(key_hex: str) -> bytes:
    """Optimized key to hash conversion"""
    try:
        priv = bytes.fromhex(key_hex)
        pub = coincurve.PublicKey.from_secret(priv).format(compressed=True)
        return hashlib.new('ripemd160', hashlib.sha256(pub).digest()).digest()
    except Exception:
        return b''

def worker(args):
    """Optimized worker function with batch processing"""
    start, end, target = args
    found = None
    last_checked = start
    processed = 0
    batch_results = []
    
    # Pre-calculate the target as numpy array for faster comparison
    target_np = np.frombuffer(target, dtype=np.uint8)
    
    for key_int in range(start, end + 1):
        if Config.FILTER_TRIVIAL:
            if Config.USE_NUMBA:
                if not numba_is_potential(key_int):
                    processed += 1
                    continue
            else:
                key_hex = f"{key_int:064x}"
                if is_trivial(key_hex[-16:]):
                    processed += 1
                    continue
        
        key_hex = f"{key_int:064x}"
        last_checked = key_int
        processed += 1
        
        # Batch processing for better performance
        batch_results.append(key_hex)
        if len(batch_results) >= 100:  # Process in batches of 100
            for k in batch_results:
                h = key_to_hash(k)
                if np.array_equal(np.frombuffer(h, dtype=np.uint8), target_np):
                    found = k
                    break
            batch_results = []
            if found:
                break
    
    # Process remaining keys in batch
    if not found and batch_results:
        for k in batch_results:
            h = key_to_hash(k)
            if np.array_equal(np.frombuffer(h, dtype=np.uint8), target_np):
                found = k
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
            'last_speed_count': 0,
            'potential_keys': 0
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
        
        # Update speed every 5 seconds
        if now - self.stats['last_speed_time'] >= 5:
            self.stats['speed'] = (self.stats['total_checked'] - self.stats['last_speed_count']) / \
                                 (now - self.stats['last_speed_time'])
            self.stats['last_speed_time'] = now
            self.stats['last_speed_count'] = self.stats['total_checked']
        
        if force_print or time_since_last_print >= Config.PROGRESS_INTERVAL:
            remaining = max(0, (Config.END - self.current) / max(self.stats['speed'], 1e-9))
            
            print(f"\n[Progress] Checked: {self.stats['total_checked']:,} | "
                  f"Potential: {self.stats['potential_keys']:,} | "
                  f"Speed: {self.stats['speed']/1e6:.2f} Mkeys/sec | "
                  f"Progress: {(self.current-Config.START)/(Config.END-Config.START)*100:.2f}% | "
                  f"Last key: {hex(self.last_checked)} | "
                  f"ETA: {remaining/3600:.1f} hours")
            
            self.last_print_time = now

    def run(self):
        print(f"Starting scan from {hex(Config.START)} to {hex(Config.END)}")
        print(f"Target hash: {Config.TARGET.hex()}")
        print(f"Using cores: {multiprocessing.cpu_count()}")
        print(f"Using Numba: {Config.USE_NUMBA}")
        print(f"Filtering trivial keys: {Config.FILTER_TRIVIAL}")
        
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
                    # Count potential keys (those that passed filters)
                    self.stats['potential_keys'] += result['processed']
                
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
    solver = Solver(target_address)
    
    # Warm up Numba
    if Config.USE_NUMBA:
        print("Warming up Numba...")
        numba_is_potential(0x123456789abcdef0)
    
    solver.run()
