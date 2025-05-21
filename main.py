import hashlib
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
    'TARGET_RIPEMD': bytes.fromhex("f6f5431d25bbf7b12e8add9af5e3475c44a0a5b8"),  # Замените на ваш хеш
    'START_KEY': 0x60102a304a78f26a80,
    'END_KEY': 0x7fffffffffffffffff,
    'BATCH_PER_CORE': 10_000_000,
    'MAX_RETRIES': 3
}

def init_shared_stats(s):
    global shared_stats
    shared_stats = s

def is_junk_key(key_hex: str) -> bool:
    significant_part = key_hex[-18:]
    for c in '0123456789abcdef':
        if c*5 in significant_part:
            return True
    return False

def key_to_ripemd160(private_key_hex: str) -> Optional[bytes]:
    try:
        priv = bytes.fromhex(private_key_hex)
        pub_key = coincurve.PublicKey.from_valid_secret(priv).format(compressed=True)
        sha256 = hashlib.sha256(pub_key).digest()
        ripemd = hashlib.new('ripemd160', sha256).digest()
        return ripemd
    except Exception:
        return None

def load_checkpoint() -> int:
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
        except (json.JSONDecodeError, KeyError) as e:
            print(f"{Colors.RED}Checkpoint corrupted, attempt {_+1}/{CONFIG['MAX_RETRIES']}: {e}{Colors.END}")
            time.sleep(1)
    
    print(f"{Colors.RED}Fatal: Could not load checkpoint, resetting to start{Colors.END}")
    return CONFIG['START_KEY']

def atomic_save_checkpoint(current_key: int, stats):
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
                }, f)
            
            os.replace(temp_file, CONFIG['CHECKPOINT_FILE'])
            return
        except Exception as e:
            print(f"{Colors.RED}Error saving checkpoint (attempt {_+1}): {e}{Colors.END}")
            time.sleep(1)
    
    print(f"{Colors.RED}Fatal: Could not save checkpoint{Colors.END}")

def process_key_batch(start_key: int, end_key: int, target: bytes, stats):
    local_checked = 0
    local_skipped = 0
    
    for k in range(start_key, end_key + 1):
        private_key = f"{k:064x}"
        
        if is_junk_key(private_key):
            local_skipped += 1
            continue
            
        if (ripemd := key_to_ripemd160(private_key)) and ripemd == target:
            stats['keys_found'] += 1
            return private_key
        
        local_checked += 1
        if local_checked % 100_000 == 0:
            stats['keys_checked'] += local_checked
            stats['keys_skipped'] += local_skipped
            local_checked = 0
            local_skipped = 0
    
    stats['keys_checked'] += local_checked
    stats['keys_skipped'] += local_skipped
    return None

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
        
        if keys_per_sec > 1_000_000:
            speed_str = f"{keys_per_sec/1_000_000:.2f} M keys/sec"
        else:
            speed_str = f"{keys_per_sec:,.0f} keys/sec"
        
        print(
            f"{Colors.YELLOW}[Status] Keys: {stats['keys_checked']:,} | "
            f"Skipped: {stats['keys_skipped']:,} | "
            f"Speed: {speed_str} | "
            f"Current: {hex(self.current_key)} | "
            f"Elapsed: {elapsed/60:.1f} min{Colors.END}"
        )

    def run(self):
        print(f"{Colors.YELLOW}Target RIPEMD-160: {CONFIG['TARGET_RIPEMD'].hex()}{Colors.END}")
        print(f"Search range: {hex(CONFIG['START_KEY'])} - {hex(CONFIG['END_KEY'])}")
        print(f"{Colors.BLUE}Filtering obvious junk keys (sequences/repeats){Colors.END}")
        
        if self.current_key > CONFIG['START_KEY']:
            print(f"{Colors.BLUE}Resuming from checkpoint: {hex(self.current_key)}{Colors.END}")
        
        num_cores = multiprocessing.cpu_count()
        print(f"{Colors.BLUE}Using {num_cores} CPU cores{Colors.END}")
        print(f"{Colors.YELLOW}Status updates every minute{Colors.END}\n")
        
        manager = multiprocessing.Manager()
        shared_stats = manager.dict({
            'keys_checked': 0,
            'keys_found': 0,
            'keys_skipped': 0
        })
        
        pool = multiprocessing.Pool(processes=num_cores, initializer=init_shared_stats, initargs=(shared_stats,))
        last_status_time = time.time()
        found_key = None
        batch_size = CONFIG['BATCH_PER_CORE'] * num_cores * 2

        try:
            while self.current_key <= CONFIG['END_KEY'] and not found_key and not self.should_stop:
                batch_end = min(self.current_key + batch_size - 1, CONFIG['END_KEY'])
                
                keys_per_core = (batch_end - self.current_key + 1) // num_cores
                tasks = []
                for i in range(num_cores):
                    start = self.current_key + i * keys_per_core
                    end = start + keys_per_core - 1 if i < num_cores - 1 else batch_end
                    tasks.append((start, end, CONFIG['TARGET_RIPEMD'], shared_stats))
                
                results = pool.starmap(process_key_batch, tasks)
                
                for result in results:
                    if result:
                        found_key = result
                        break
                
                self.current_key = batch_end + 1
                
                if shared_stats['keys_checked'] % CONFIG['SAVE_INTERVAL'] == 0:
                    atomic_save_checkpoint(self.current_key - 1, shared_stats)
                
                if time.time() - last_status_time >= CONFIG['STATUS_INTERVAL']:
                    self.print_status(shared_stats)
                    last_status_time = time.time()
            
            if found_key:
                print(f"\n{Colors.GREEN}SUCCESS: Key found!{Colors.END}")
                print(f"Private key: {found_key}")
                with open(CONFIG['FOUND_KEYS_FILE'], 'a') as f:
                    f.write(f"{time.ctime()}\n")
                    f.write(f"Private: {found_key}\n")
                    f.write(f"RIPEMD-160: {CONFIG['TARGET_RIPEMD'].hex()}\n\n")
            elif self.should_stop:
                print(f"\n{Colors.YELLOW}SEARCH STOPPED{Colors.END}")
            else:
                print(f"\n{Colors.BLUE}SEARCH COMPLETED{Colors.END}")
                print(f"{Colors.YELLOW}Target key not found in specified range{Colors.END}")
                
        except Exception as e:
            print(f"\n{Colors.RED}Error: {e}{Colors.END}")
        finally:
            pool.close()
            pool.join()
            
            if not found_key and self.current_key > CONFIG['START_KEY']:
                atomic_save_checkpoint(self.current_key - 1, shared_stats)
            
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
        return f"{speed:,.0f} keys/sec"

if __name__ == "__main__":
    multiprocessing.freeze_support()
    searcher = KeySearcher()
    searcher.run()
