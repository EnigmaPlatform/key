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
import cython  # Импортируем Cython

# Критически важные функции вынесены в отдельный Cython-модуль
# Для этого создадим файл key_checks.pyx и скомпилируем его
"""
# key_checks.pyx
import cython

@cython.boundscheck(False)
@cython.wraparound(False)
def is_valid_key(key_hex: str) -> cython.bint:
    # Игнорируем ведущие нули (первые 46 символов)
    significant_part = key_hex[46:]
    
    # 1. Проверка на ключи только из цифр или только из букв
    if significant_part.isdigit() or significant_part.isalpha():
        return False
    
    # 2. Проверка на более 4 повторяющихся символов подряд
    cdef int i, count = 1
    cdef char current = significant_part[0]
    for i in range(1, len(significant_part)):
        if significant_part[i] == current:
            count += 1
            if count > 4:
                return False
        else:
            current = significant_part[i]
            count = 1
    
    return True
"""

# Импортируем скомпилированную Cython-функцию
from key_checks import is_valid_key

class Config:
    FOUND_FILE = "found.txt"
    TARGET_HASH = None
    START = 0x349b84b6431a5c4ef1
    END = 0x349b84b6431a6c4ef1
    CHUNK_SIZE = 100000  # Увеличенный размер блока
    THREADS = multiprocessing.cpu_count()

def process_key(key: int) -> tuple:
    """Оптимизированная обработка одного ключа"""
    try:
        key_hex = f"{key:064x}"
        
        if not is_valid_key(key_hex):
            return (None, None, 0)
        
        key_bytes = key.to_bytes(32, 'big')
        pub_key = coincurve.PublicKey.from_secret(key_bytes).format(compressed=True)
        h = SHA256.new(pub_key).digest()
        h = RIPEMD160.new(h).digest()
        return (key_hex, h, 1)
    except:
        return (None, None, 0)

def worker(start: int, end: int) -> dict:
    """Оптимизированная рабочая функция"""
    found = None
    processed = 0
    valid = 0
    last_checked = start
    
    results = []
    batch_size = 1000  # Размер мини-пакета для обработки
    
    for batch_start in range(start, end + 1, batch_size):
        batch_end = min(batch_start + batch_size - 1, end)
        
        # Обрабатываем мини-пакет
        for key in range(batch_start, batch_end + 1):
            key_hex, h, is_valid = process_key(key)
            processed += 1
            valid += is_valid
            
            if h is not None and h == Config.TARGET_HASH:
                found = key_hex
                break
                
            last_checked = key
        
        if found:
            break
    
    return {
        'found': found,
        'processed': processed,
        'valid': valid,
        'last_checked': last_checked
    }

class KeySolver:
    def __init__(self, target_address=None):
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
        
        Config.TARGET_HASH = (b58decode_check(target_address)[1:] if target_address 
                            else bytes.fromhex("5db8cda53a6a002db10365967d7f85d19e171b10"))

    def signal_handler(self, signum, frame):
        print("\nПолучен сигнал прерывания, завершаем работу...")
        self.should_stop = True

    def print_progress(self):
        current_time = time.time()
        elapsed = current_time - self.stats['start_time']
        
        if current_time - self.stats['last_check'] >= 5:
            self.stats['speed'] = self.stats['total'] / elapsed
            self.stats['last_check'] = current_time
        
        remaining = max(0, Config.END - self.stats['last_key'])
        eta = remaining / max(self.stats['speed'], 1)
        
        print(f"\n[Прогресс] Всего: {self.stats['total']:,} | "
              f"Действительных: {self.stats['valid']:,} | "
              f"Скорость: {self.stats['speed']:,.0f} key/sec | "
              f"Прогресс: {100*(self.stats['last_key']-Config.START)/(Config.END-Config.START):.2f}% | "
              f"Последний: {hex(self.stats['last_key'])} | "
              f"Осталось: {eta/3600:.1f} ч")

    def run(self):
        print(f"Сканирование: {hex(Config.START)} - {hex(Config.END)}")
        print(f"Целевой хеш: {Config.TARGET_HASH.hex()}")
        print(f"Потоков: {Config.THREADS}")
        print("Фильтрация:")
        print("- Макс 4 повторяющихся символа подряд (исключая 46 ведущих нулей)")
        print("- Не только цифры или только буквы")
        
        try:
            with ProcessPoolExecutor(max_workers=Config.THREADS) as executor:
                futures = []
                
                while self.current <= Config.END and not self.should_stop:
                    chunk_end = min(self.current + Config.CHUNK_SIZE - 1, Config.END)
                    futures.append(executor.submit(worker, self.current, chunk_end))
                    self.current = chunk_end + 1
                    
                    # Обрабатываем завершенные задачи
                    while futures:
                        done, _ = as_completed(futures), []
                        for future in done:
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
            print(f"\nОшибка: {str(e)}")
        
        print("\nЗавершено" + (" (прервано)" if self.should_stop else " - ключ не найден"))

    def key_found(self, key):
        print(f"\n\n!!! НАЙДЕН КЛЮЧ !!!")
        print(f"Приватный ключ: {key}")
        print(f"Хеш: {Config.TARGET_HASH.hex()}")
        
        with open(Config.FOUND_FILE, 'a', encoding='utf-8') as f:
            f.write(f"{time.ctime()}\n{key}\n")

if __name__ == "__main__":
    if os.name == 'posix':
        multiprocessing.set_start_method('fork')
    
    target_address = sys.argv[1] if len(sys.argv) > 1 else None
    solver = KeySolver(target_address)
    solver.run()
