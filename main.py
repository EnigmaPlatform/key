# -*- coding: utf-8 -*-
import multiprocessing
import time
import os
import sys
import signal
from concurrent.futures import ProcessPoolExecutor, as_completed
from Crypto.Hash import RIPEMD160, SHA256
from base58 import b58decode_check
import re
import coincurve

class Config:
    FOUND_FILE = "found.txt"
    LOG_FILE = "scan.log"
    TARGET_HASH = bytes.fromhex("5db8cda53a6a002db10365967d7f85d19e171b10")
    START = 0x349b84b6431a5c4ef1
    END = 0x349b84b6431a6c4ef1 + 1  # Добавляем +1 чтобы включить последний ключ
    CHUNK_SIZE = 50000
    THREADS = multiprocessing.cpu_count()

def is_valid_key(key_hex: str) -> bool:
    """Проверка ключа по всем критериям"""
    significant_part = key_hex[46:]  # Игнорируем 46 ведущих нулей
    
    # 1. Не только цифры или только буквы
    if significant_part.isdigit() or significant_part.isalpha():
        return False
    
    # 2. Не более 4 одинаковых символов подряд
    if re.search(r'(.)\1{4}', significant_part):
        return False
    
    return True

def key_to_hash(key: int) -> tuple:
    """Оптимизированное преобразование ключа в хеш"""
    try:
        key_hex = f"{key:064x}"
        
        if not is_valid_key(key_hex):
            return (None, None)
        
        key_bytes = bytes.fromhex(key_hex)
        pub_key = coincurve.PublicKey.from_secret(key_bytes).format(compressed=True)
        h = RIPEMD160.new(SHA256.new(pub_key).digest()).digest()
        return (key_hex, h)
    except Exception as e:
        return (None, None)

def worker(start: int, end: int) -> dict:
    """Рабочая функция с проверкой каждого ключа"""
    found = None
    processed = 0
    valid = 0
    last_checked = start
    
    for key in range(start, end):
        key_hex, h = key_to_hash(key)
        processed += 1
        
        if h is not None:
            valid += 1
            if h == Config.TARGET_HASH:
                found = key_hex
                break
        
        last_checked = key
    
    return {
        'found': found,
        'processed': processed,
        'valid': valid,
        'last_checked': last_checked
    }

class KeySolver:
    def __init__(self):
        self.current = Config.START
        self.stats = {
            'total': 0,
            'valid': 0,
            'speed': 0,
            'start_time': time.time(),
            'last_check': time.time(),
            'last_key': Config.START
        }
        self.should_stop = False
        signal.signal(signal.SIGINT, self.signal_handler)
        
        # Очищаем файлы логов
        open(Config.FOUND_FILE, 'w').close()
        open(Config.LOG_FILE, 'w').close()
        
        self.log(f"Начало сканирования: {hex(Config.START)} - {hex(Config.END-1)}")
        self.log(f"Целевой хеш: {Config.TARGET_HASH.hex()}")
        self.log(f"Всего ключей: {Config.END - Config.START:,}")
        self.log(f"Потоков: {Config.THREADS}")

    def log(self, message):
        with open(Config.LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"{time.ctime()} - {message}\n")

    def signal_handler(self, signum, frame):
        print("\nПолучен сигнал прерывания, завершаем работу...")
        self.should_stop = True
        self.log("Сканирование прервано пользователем")

    def print_progress(self):
        current_time = time.time()
        elapsed = current_time - self.stats['start_time']
        
        if current_time - self.stats['last_check'] >= 5:
            self.stats['speed'] = self.stats['total'] / elapsed
            self.stats['last_check'] = current_time
        
        remaining = max(0, Config.END - self.stats['last_key'])
        eta = remaining / max(self.stats['speed'], 1)
        
        progress = 100*(self.stats['last_key']-Config.START)/(Config.END-Config.START)
        
        print(f"\n[Прогресс] Всего: {self.stats['total']:,} | "
              f"Действительных: {self.stats['valid']:,} | "
              f"Скорость: {self.stats['speed']:,.0f} key/sec | "
              f"Прогресс: {progress:.2f}% | "
              f"Последний: {hex(self.stats['last_key'])} | "
              f"Осталось: {eta/3600:.1f} ч")

    def run(self):
        print(f"Сканирование диапазона: {hex(Config.START)} - {hex(Config.END-1)}")
        print(f"Целевой хеш: {Config.TARGET_HASH.hex()}")
        print(f"Потоков: {Config.THREADS}")
        print("Критерии фильтрации:")
        print("- Не более 4 одинаковых символов подряд (исключая 46 ведущих нулей)")
        print("- Не только цифры или только буквы")
        
        try:
            with ProcessPoolExecutor(max_workers=Config.THREADS) as executor:
                futures = []
                
                while self.current < Config.END and not self.should_stop:
                    chunk_end = min(self.current + Config.CHUNK_SIZE, Config.END)
                    futures.append(executor.submit(worker, self.current, chunk_end))
                    self.current = chunk_end
                    
                    # Обработка завершенных задач
                    for future in as_completed(futures):
                        result = future.result()
                        
                        self.stats['total'] += result['processed']
                        self.stats['valid'] += result['valid']
                        self.stats['last_key'] = max(self.stats['last_key'], result['last_checked'])
                        
                        if result['found']:
                            self.key_found(result['found'])
                            return
                            
                        futures.remove(future)
                        self.print_progress()
                        break
                
                # Завершение оставшихся задач
                for future in as_completed(futures):
                    if self.should_stop:
                        break
                        
                    result = future.result()
                    self.stats['total'] += result['processed']
                    self.stats['valid'] += result['valid']
                    self.stats['last_key'] = max(self.stats['last_key'], result['last_checked'])
                    
                    if result['found']:
                        self.key_found(result['found'])
                        return
                        
                    self.print_progress()
                    
        except Exception as e:
            error_msg = f"Ошибка: {str(e)}"
            print(error_msg)
            self.log(error_msg)
        
        print("\nЗавершено" + (" (прервано)" if self.should_stop else " - ключ не найден"))
        self.log(f"Всего проверено: {self.stats['total']:,} ключей")
        self.log(f"Действительных ключей: {self.stats['valid']:,}")

    def key_found(self, key):
        print(f"\n\n!!! НАЙДЕН КЛЮЧ !!!")
        print(f"Приватный ключ: {key}")
        print(f"Хеш: {Config.TARGET_HASH.hex()}")
        
        with open(Config.FOUND_FILE, 'a') as f:
            f.write(f"{time.ctime()}\n{key}\n")
        self.log(f"Найден ключ: {key}")

if __name__ == "__main__":
    if os.name == 'posix':
        multiprocessing.set_start_method('fork')
    
    solver = KeySolver()
    solver.run()
