import hashlib
import base58
import time
import json
import os
import coincurve
from threading import Thread, Lock
from queue import Queue

CONFIG = {
    'TARGET_ADDRESS': "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU",
    'START_KEY': 0x1A12F1DA9D7000000,
    'END_KEY': 0x1A12F1DA9DFFFFFFF,
    'CHECKPOINT_FILE': 'progress.json',
    'FOUND_KEYS_FILE': 'found_key.txt',
    'BATCH_SIZE': 1_000_000,  # Увеличиваем размер блока для каждого потока
    'THREADS': max(1, os.cpu_count() - 1),  # Оптимальное число потоков
    'STATUS_INTERVAL': 5
}

class KeyScanner:
    def __init__(self):
        self.lock = Lock()
        self.progress = self.load_progress()
        self.current_batch = self.progress.get('last_batch', 0)
        self.keys_checked = self.progress.get('keys_checked', 0)
        self.start_time = time.time()
        self.found = False
        self.queue = Queue()
        self.workers = []

    def load_progress(self):
        if os.path.exists(CONFIG['CHECKPOINT_FILE']):
            try:
                with open(CONFIG['CHECKPOINT_FILE'], 'r') as f:
                    return json.load(f)
            except:
                pass
        return {'last_batch': 0, 'keys_checked': 0, 'checked_ranges': []}

    def save_progress(self):
        progress = {
            'last_batch': self.current_batch,
            'keys_checked': self.keys_checked,
            'checked_ranges': self.progress['checked_ranges'],
            'timestamp': time.time()
        }
        with open(CONFIG['CHECKPOINT_FILE'], 'w') as f:
            json.dump(progress, f)

    def private_to_address(self, private_key_hex):
        priv = bytes.fromhex(private_key_hex)
        pub = coincurve.PublicKey.from_valid_secret(priv).format(compressed=True)
        h160 = hashlib.new('ripemd160', hashlib.sha256(pub).digest()).digest()
        extended = b'\x00' + h160
        checksum = hashlib.sha256(hashlib.sha256(extended).digest()).digest()[:4]
        return base58.b58encode(extended + checksum).decode('utf-8')

    def worker(self):
        while not self.found:
            batch = self.get_next_batch()
            if batch is None:
                break

            start, end = batch
            found_in_batch = False
            
            for key in range(start, end + 1):
                if self.found:
                    break
                    
                private_key = f"{key:064x}"
                address = self.private_to_address(private_key)
                
                if address == CONFIG['TARGET_ADDRESS']:
                    with self.lock:
                        self.found = True
                        print(f"\n\n>>> КЛЮЧ НАЙДЕН! <<<")
                        print(f"Приватный ключ: {private_key}")
                        print(f"Hex: {hex(key)}")
                        with open(CONFIG['FOUND_KEYS_FILE'], "w") as f:
                            f.write(f"Адрес: {CONFIG['TARGET_ADDRESS']}\n")
                            f.write(f"Ключ: {private_key}\n")
                            f.write(f"Hex: {hex(key)}\n")
                    found_in_batch = True
                    break

            self.update_progress(end, (end - start + 1))
            
    def get_next_batch(self):
        with self.lock:
            if self.found:
                return None
                
            batch_start = CONFIG['START_KEY'] + self.current_batch * CONFIG['BATCH_SIZE']
            if batch_start > CONFIG['END_KEY']:
                return None
                
            batch_end = min(batch_start + CONFIG['BATCH_SIZE'] - 1, CONFIG['END_KEY'])
            self.current_batch += 1
            return (batch_start, batch_end)

    def update_progress(self, last_key, keys_processed):
        with self.lock:
            self.keys_checked += keys_processed
            self.progress['checked_ranges'].append({
                'start': last_key - keys_processed + 1,
                'end': last_key,
                'keys': keys_processed
            })

    def run(self):
        print("\n=== Bitcoin Puzzle Solver ===")
        print(f"Целевой адрес: {CONFIG['TARGET_ADDRESS']}")
        print(f"Диапазон: {hex(CONFIG['START_KEY'])} - {hex(CONFIG['END_KEY'])}")
        print(f"Всего ключей: {(CONFIG['END_KEY']-CONFIG['START_KEY']+1):,}")
        print(f"Размер блока: {CONFIG['BATCH_SIZE']:,}")
        print(f"Потоков: {CONFIG['THREADS']}")
        print("==============================")

        # Запуск рабочих потоков
        for _ in range(CONFIG['THREADS']):
            t = Thread(target=self.worker)
            t.start()
            self.workers.append(t)

        try:
            last_status = time.time()
            while not self.found and any(t.is_alive() for t in self.workers):
                time.sleep(0.1)
                
                if time.time() - last_status >= CONFIG['STATUS_INTERVAL']:
                    elapsed = time.time() - self.start_time
                    with self.lock:
                        speed = int(self.keys_checked / elapsed) if elapsed > 0 else 0
                        total_keys = CONFIG['END_KEY'] - CONFIG['START_KEY'] + 1
                        percent = (self.keys_checked / total_keys) * 100
                        
                        print(f"\r[Прогресс] {percent:.2f}% | "
                              f"Ключей: {self.keys_checked:,} | "
                              f"Скорость: {speed:,} keys/s | "
                              f"Блоков: {self.current_batch}", end="", flush=True)
                    
                    last_status = time.time()
                    self.save_progress()
        
        except KeyboardInterrupt:
            print("\nОстановлено пользователем. Сохраняем прогресс...")
            self.found = True
        
        for t in self.workers:
            t.join()

        elapsed = time.time() - self.start_time
        print(f"\n\nИтоги:")
        print(f"Проверено ключей: {self.keys_checked:,}")
        print(f"Проверено блоков: {self.current_batch}")
        print(f"Общее время: {elapsed:.1f} секунд")
        print(f"Средняя скорость: {int(self.keys_checked/elapsed):,} keys/s")
        self.save_progress()

if __name__ == "__main__":
    scanner = KeyScanner()
    scanner.run()
