import hashlib
import base58
import time
import json
import os
import coincurve
from threading import Thread, Lock
from queue import Queue

# Конфигурация
CONFIG = {
    'TARGET_ADDRESS': "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU",
    'START_KEY': 0x1A12F1DA9D7000000,
    'END_KEY': 0x1A12F1DA9DFFFFFFF,
    'CHECKPOINT_FILE': 'progress.json',
    'FOUND_KEYS_FILE': 'found_key.txt',
    'BATCH_SIZE': 10_000_000,  # Размер диапазона для сохранения
    'THREADS': 8,  # Количество потоков
    'STATUS_INTERVAL': 5  # секунды между обновлениями статуса
}

class KeyScanner:
    def __init__(self):
        self.lock = Lock()
        self.progress = self.load_progress()
        self.current_key = self.progress['last_key']
        self.keys_checked = self.progress['keys_checked']
        self.last_saved_batch = self.current_key // CONFIG['BATCH_SIZE']
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
        return {'last_key': CONFIG['START_KEY'], 'keys_checked': 0, 'checked_ranges': []}

    def save_progress(self):
        with self.lock:
            progress = {
                'last_key': self.current_key,
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
            key = self.get_next_key()
            if key is None:
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
                break

            self.update_progress(key)

    def get_next_key(self):
        with self.lock:
            if self.current_key > CONFIG['END_KEY'] or self.found:
                return None
            key = self.current_key
            self.current_key += 1
            return key

    def update_progress(self, key):
        with self.lock:
            self.keys_checked += 1
            
            # Проверяем нужно ли сохранить этот диапазон
            current_batch = key // CONFIG['BATCH_SIZE']
            if current_batch > self.last_saved_batch:
                batch_start = current_batch * CONFIG['BATCH_SIZE']
                batch_end = (current_batch + 1) * CONFIG['BATCH_SIZE'] - 1
                self.progress['checked_ranges'].append({
                    'start': batch_start,
                    'end': batch_end,
                    'keys': CONFIG['BATCH_SIZE']
                })
                self.last_saved_batch = current_batch
                self.save_progress()

    def format_speed(self, speed):
        if speed >= 1_000_000:
            return f"{speed/1_000_000:.1f}M keys/s"
        return f"{speed/1_000:.1f}K keys/s"

    def run(self):
        print("\n=== Bitcoin Puzzle Solver ===")
        print(f"Целевой адрес: {CONFIG['TARGET_ADDRESS']}")
        print(f"Диапазон: {hex(CONFIG['START_KEY'])} - {hex(CONFIG['END_KEY'])}")
        print(f"Всего ключей: {(CONFIG['END_KEY']-CONFIG['START_KEY']+1):,}")
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
                        remaining = (total_keys - self.keys_checked) / speed if speed > 0 else 0
                        
                        print(f"\r[Прогресс] {percent:.2f}% | "
                              f"Ключей: {self.keys_checked:,} | "
                              f"Скорость: {self.format_speed(speed)} | "
                              f"Текущий: {hex(self.current_key)}", end="", flush=True)
                    
                    last_status = time.time()
        
        except KeyboardInterrupt:
            print("\nОстановлено пользователем. Сохраняем прогресс...")
            self.found = True
        
        for t in self.workers:
            t.join()

        elapsed = time.time() - self.start_time
        print(f"\n\nПоиск завершен. Проверено ключей: {self.keys_checked:,}")
        print(f"Общее время: {elapsed:.1f} секунд")
        print(f"Средняя скорость: {self.format_speed(int(self.keys_checked/elapsed))}")
        print(f"Последняя позиция: {hex(self.current_key)}")
        self.save_progress()

if __name__ == "__main__":
    scanner = KeyScanner()
    scanner.run()
