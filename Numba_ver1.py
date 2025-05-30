# -*- coding: utf-8 -*-
import hashlib
import coincurve
from concurrent.futures import ProcessPoolExecutor
import time
import os
import threading
from multiprocessing import freeze_support
from colorama import init, Fore, Back, Style
import sys
import secrets
import gc
from typing import Dict, Tuple, List
import numpy as np
from numba import njit
import shutil
import psutil
from math import isfinite

# Инициализация colorama
init(autoreset=True)

# Конфигурация
CONFIG = {
    "target_hash": "f6f5431d25bbf7b12e8add9af5e3475c44a0a5b8",
    "start_range": 0x400000000000000000,
    "end_range": 0x7fffffffffffffffff,
    "num_threads": 12,
    "check_range": 99_000_000,
    "chunk_size": 9_900_000,
    "max_attempts": 1_000_000,
    "state_dir": "progress_states",
    "backup_dir": "backups",
    "max_backups": 5,
    "update_interval": 1.0,
    "backup_interval": 300,
    "max_repeats": 4,
    "max_sequence": 4,
    "max_similar": 5,
    "min_key_length": 64,
    "gc_interval": 1_000_000,
    "block_delay": 0.5,
    "memory_limit": 0.85,
    "cpu_limit": 0.90,
    "overflow_check_interval": 1000,
    "memory_warning_threshold": 500,
    "min_clear_interval": 5,
    "gc_collect_interval": 10,
    "max_display_value": 1_000_000_000_000_000_000  # Максимальное значение для отображения (1 квинтиллион)
}

class BlockCounter:
    def __init__(self):
        self.count = 0
        self.last_clear = 0
        self.lock = threading.Lock()
    
    def increment(self):
        with self.lock:
            self.count += 1
    
    def get_count(self):
        with self.lock:
            return self.count
    
    def needs_clear(self):
        with self.lock:
            return (self.count - self.last_clear) >= CONFIG['min_clear_interval']

block_counter = BlockCounter()

class Logger:
    def __init__(self):
        self.lock = threading.Lock()
    
    def log(self, message):
        with self.lock:
            print(message)
            sys.stdout.flush()

logger = Logger()

def init_worker():
    """Инициализация worker-процесса"""
    if os.name == 'nt':
        try:
            import win32api, win32process, win32con
            handle = win32api.GetCurrentProcess()
            win32process.SetPriorityClass(handle, win32process.BELOW_NORMAL_PRIORITY_CLASS)
        except ImportError:
            pass
    else:
        try:
            os.nice(5)
        except:
            pass

@njit
def is_sequence_numba(s: str) -> bool:
    """Проверка последовательностей с Numba"""
    if len(s) < 2:
        return False
    
    delta = ord(s[1]) - ord(s[0])
    if delta == 0:
        return False
        
    for i in range(1, len(s)-1):
        if ord(s[i+1]) - ord(s[i]) != delta:
            return False
    return True

def is_valid_key(key_hex: str) -> bool:
    """Оптимизированная проверка ключа"""
    try:
        if len(key_hex) != CONFIG['min_key_length']:
            return False
        
        if not key_hex.startswith('0'*46) or key_hex[46] not in '4567':
            return False
        
        last_17 = key_hex[-17:]
        
        if any(seq in last_17 for seq in ['11111', 'aaaaa', '22222', 'bbbbb']):
            return False
        
        for i in range(len(last_17) - CONFIG['max_repeats']):
            if len(set(last_17[i:i+CONFIG['max_repeats']+1])) == 1:
                return False
        
        for i in range(len(last_17) - CONFIG['max_sequence']):
            if is_sequence_numba(last_17[i:i+CONFIG['max_sequence']+1]):
                return False
        
        return True
    except:
        return False

def generate_valid_random_key() -> Tuple[int, str]:
    """Генерация валидного ключа"""
    chars = '0123456789abcdef'
    first_chars = '4567'
    
    for _ in range(10_000):
        try:
            first_char = secrets.choice(first_chars)
            random_part = ''.join(secrets.choice(chars) for _ in range(17))
            key_hex = '0'*46 + first_char + random_part
            
            if is_valid_key(key_hex):
                key_int = int(key_hex, 16)
                if CONFIG['start_range'] <= key_int <= CONFIG['end_range']:
                    return (key_int, key_hex)
        except:
            continue
    
    raise ValueError("Не удалось сгенерировать валидный ключ")

def optimized_clear_caches():
    """Оптимизированная очистка кешей"""
    try:
        if block_counter.needs_clear():
            hashlib._hashlib.openssl_sha256.sha256.__dict__.clear()
            hashlib._hashlib.openssl_ripemd160.ripemd160.__dict__.clear()
            if hasattr(coincurve, '_cache'):
                coincurve._cache.clear()
            block_counter.last_clear = block_counter.get_count()
    except Exception as e:
        logger.log(f"{Fore.YELLOW}Ошибка очистки кешей: {e}{Style.RESET_ALL}")

def check_memory():
    """Проверка использования памяти"""
    try:
        process = psutil.Process(os.getpid())
        mem = process.memory_info().rss / 1024 / 1024
        if mem > CONFIG['memory_warning_threshold']:
            logger.log(f"{Fore.YELLOW}Предупреждение: использование памяти {mem:.2f}MB{Style.RESET_ALL}")
            return True
        return False
    except Exception as e:
        logger.log(f"{Fore.YELLOW}Ошибка проверки памяти: {e}{Style.RESET_ALL}")
        return False

def check_system_limits():
    """Проверка системных ограничений"""
    try:
        mem = psutil.virtual_memory()
        cpu = psutil.cpu_percent(interval=0.1)
        
        if mem.percent / 100 > CONFIG['memory_limit']:
            return False
        
        if cpu / 100 > CONFIG['cpu_limit']:
            return False
        
        return True
    except Exception as e:
        logger.log(f"{Fore.YELLOW}Ошибка проверки системных ограничений: {e}{Style.RESET_ALL}")
        return True

def process_key(key_int: int, target_hash: str) -> Tuple[bool, str]:
    """Обработка ключа с проверкой хеша"""
    try:
        key_hex = "%064x" % key_int
        if not isfinite(key_int) or not is_valid_key(key_hex):
            return (False, "")
        
        key_bytes = bytes.fromhex(key_hex)
        pub_key = coincurve.PublicKey.from_secret(key_bytes).format(compressed=True)
        pub_key_hash = hashlib.sha256(pub_key).digest()
        h = hashlib.new('ripemd160', pub_key_hash).hexdigest()
        
        return (h == target_hash, key_hex)
    except Exception as e:
        return (False, "")

def process_range(start_key: int, end_key: int, thread_id: int):
    """Обработка диапазона ключей"""
    progress_file = os.path.join(CONFIG['state_dir'], f"thread_{thread_id}.progress")
    checked = 0
    
    try:
        os.makedirs(CONFIG['state_dir'], exist_ok=True)
        with open(progress_file, 'w') as f:
            f.write(f"START {start_key} {end_key}\n")
        
        current = start_key
        while current <= end_key:
            found, key_hex = process_key(current, CONFIG['target_hash'])
            if found:
                with open(progress_file, 'a') as f:
                    f.write(f"FOUND {key_hex}\n")
                return
            
            checked += 1
            current += 1
            
            if checked % 100_000 == 0:
                with open(progress_file, 'a') as f:
                    f.write(f"PROGRESS {current}\n")
    
    except Exception as e:
        with open(progress_file, 'a') as f:
            f.write(f"ERROR {str(e)}\n")
    finally:
        with open(progress_file, 'a') as f:
            f.write(f"END {checked}\n")

def print_progress_bar(iteration, total, prefix='', suffix='', length=50, fill='█'):
    """Безопасное отображение прогресс-бара с защитой от переполнения"""
    try:
        # Защита от некорректных значений
        total = max(1, total)
        iteration = max(0, min(iteration, total))
        
        # Ограничение слишком больших значений для отображения
        display_iter = min(iteration, CONFIG['max_display_value'])
        display_total = min(total, CONFIG['max_display_value'])
        
        percent = min(100, (display_iter / display_total) * 100)
        filled_length = min(length, int(length * display_iter // display_total))
        bar = fill * filled_length + '-' * (length - filled_length)
        
        return f"{prefix} |{bar}| {percent:.1f}% {display_iter:,}/{display_total:,} {suffix}"
    except Exception as e:
        return f"{prefix} | [ошибка: {str(e)}] | {suffix}"

def monitor_progress(total_keys: int, num_threads: int):
    """Мониторинг прогресса с защитой от переполнения"""
    stats = {i: {'current': 0, 'start': 0, 'end': 0} for i in range(num_threads)}
    start_time = time.time()
    last_update = time.time()
    found = False
    
    try:
        os.makedirs(CONFIG['state_dir'], exist_ok=True)
        
        while not found:
            total_checked = 0
            any_active = False
            
            for thread_id in range(num_threads):
                progress_file = os.path.join(CONFIG['state_dir'], f"thread_{thread_id}.progress")
                
                try:
                    with open(progress_file, 'r') as f:
                        lines = f.readlines()
                    
                    for line in lines:
                        line = line.strip()
                        if not line:
                            continue
                            
                        parts = line.split()
                        if parts[0] == "FOUND":
                            logger.log(f"\n{Fore.GREEN}Найден ключ: 0x{parts[1]}{Style.RESET_ALL}")
                            found = True
                            break
                        elif parts[0] == "START":
                            try:
                                stats[thread_id]['start'] = int(parts[1])
                                stats[thread_id]['end'] = int(parts[2])
                            except (ValueError, IndexError):
                                continue
                        elif parts[0] == "PROGRESS":
                            try:
                                stats[thread_id]['current'] = int(parts[1])
                                any_active = True
                            except (ValueError, IndexError):
                                continue
                except FileNotFoundError:
                    continue
                except Exception as e:
                    logger.log(f"{Fore.YELLOW}Ошибка чтения файла прогресса: {e}{Style.RESET_ALL}")
                    continue
                
                if found:
                    break
            
            if time.time() - last_update >= CONFIG['update_interval']:
                try:
                    total_range = 0
                    completed = 0
                    valid_threads = 0
                    
                    for s in stats.values():
                        if s['current'] > 0 and s['start'] > 0 and s['end'] > 0:
                            thread_range = s['end'] - s['start']
                            thread_completed = s['current'] - s['start']
                            
                            if thread_range > 0 and 0 <= thread_completed <= thread_range:
                                total_range += thread_range
                                completed += thread_completed
                                valid_threads += 1
                    
                    if valid_threads > 0 and total_range > 0:
                        elapsed_time = max(0.1, time.time() - start_time)
                        speed = completed / elapsed_time
                        completion = (completed / total_range) * 100
                        
                        try:
                            mem = psutil.virtual_memory()
                            mem_usage = f"{mem.used/1024/1024:.1f}MB/{mem.total/1024/1024:.1f}MB ({mem.percent}%)"
                            cpu_usage = psutil.cpu_percent(interval=0.1)
                        except:
                            mem_usage = "N/A"
                            cpu_usage = "N/A"
                        
                        current_range = "0x0"
                        for s in stats.values():
                            if s['current'] > 0:
                                current_range = f"0x{s['current']:x}"
                                break
                        
                        os.system('cls' if os.name == 'nt' else 'clear')
                        
                        logger.log(f"{Fore.CYAN}=== ПРОГРЕСС ПОИСКА ===")
                        logger.log(f"Проверено: {min(completed, CONFIG['max_display_value']):,}/"
                                  f"{min(total_range, CONFIG['max_display_value']):,} ({completion:.2f}%)")
                        logger.log(f"Скорость: {min(speed, CONFIG['max_display_value']):,.0f} ключ/сек")
                        logger.log(f"Блоков: {block_counter.get_count()}")
                        logger.log(f"Память: {mem_usage}")
                        logger.log(f"CPU: {cpu_usage:.1f}%")
                        logger.log("")
                        
                        progress_bar = print_progress_bar(
                            completed,
                            total_range,
                            prefix='Прогресс',
                            suffix=''
                        )
                        logger.log(progress_bar)
                        
                        logger.log(f"\nТекущий диапазон: {current_range}")
                    else:
                        logger.log(f"{Fore.YELLOW}Ожидание данных от потоков...{Style.RESET_ALL}")
                    
                    last_update = time.time()
                except Exception as e:
                    logger.log(f"{Fore.RED}Ошибка обновления прогресса: {e}{Style.RESET_ALL}")
                    time.sleep(1)
            
            time.sleep(0.2)
                
    except KeyboardInterrupt:
        return False
    except Exception as e:
        logger.log(f"{Fore.RED}Критическая ошибка в мониторе: {e}{Style.RESET_ALL}")
        return False
    return found

def test_hashing() -> bool:
    """Тест хеширования"""
    test_vectors = [
        {
            'privkey': '0000000000000000000000000000000000000000000000000000000000000001',
            'hash160': '751e76e8199196d454941c45d1b3a323f1433bd6',
            'name': 'Минимальный ключ'
        },
        {
            'privkey': 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140',
            'hash160': 'adde4c73c7b9cee17da6c7b3e2b2eea1a0dcbe67',
            'name': 'Максимальный ключ'
        }
    ]
    
    logger.log(f"{Fore.CYAN}\n=== ТЕСТ ХЕШИРОВАНИЯ ===")
    
    all_passed = True
    for test in test_vectors:
        try:
            key_bytes = bytes.fromhex(test['privkey'])
            pub_key = coincurve.PublicKey.from_secret(key_bytes).format(compressed=True)
            pub_key_hash = hashlib.sha256(pub_key).digest()
            h = hashlib.new('ripemd160', pub_key_hash).hexdigest()
            
            if h == test['hash160']:
                logger.log(f"{Fore.GREEN}✓ {test['name']} - OK{Style.RESET_ALL}")
            else:
                logger.log(f"{Fore.RED}✗ {test['name']} - Ошибка{Style.RESET_ALL}")
                all_passed = False
        except Exception as e:
            logger.log(f"{Fore.RED}✗ {test['name']} - Ошибка: {e}{Style.RESET_ALL}")
            all_passed = False
    
    logger.log(f"{Fore.GREEN if all_passed else Fore.RED}Тест {'пройден' if all_passed else 'не пройден'}{Style.RESET_ALL}")
    return all_passed

def main():
    """Оптимизированная основная функция"""
    logger.log(f"{Fore.GREEN}Инициализация программы...{Style.RESET_ALL}")
    
    if not test_hashing():
        logger.log(f"\n{Fore.RED}Тест хеширования не пройден! Завершение работы.{Style.RESET_ALL}")
        return
    
    if os.path.exists(CONFIG['state_dir']):
        shutil.rmtree(CONFIG['state_dir'])
    
    # Отключаем автоматическую сборку мусора
    gc.disable()
    
    try:
        total_keys = CONFIG['check_range']
        
        monitor_thread = threading.Thread(
            target=monitor_progress,
            args=(total_keys, CONFIG['num_threads']),
            daemon=True
        )
        monitor_thread.start()
        time.sleep(1)
        
        executor = ProcessPoolExecutor(
            max_workers=CONFIG['num_threads'],
            initializer=init_worker
        )
        
        try:
            while True:
                if not check_system_limits():
                    logger.log(f"{Fore.YELLOW}Системные ограничения превышены. Пауза...{Style.RESET_ALL}")
                    time.sleep(2)
                    continue
                
                start_key, current_key_hex = generate_valid_random_key()
                block_counter.increment()
                
                futures = []
                for i in range(CONFIG['num_threads']):
                    chunk_start = start_key + i * CONFIG['chunk_size']
                    chunk_end = chunk_start + CONFIG['chunk_size'] - 1
                    
                    if i == CONFIG['num_threads'] - 1:
                        chunk_end = start_key + CONFIG['check_range'] - 1
                    
                    futures.append(executor.submit(
                        process_range,
                        chunk_start,
                        chunk_end,
                        i
                    ))
                
                for future in futures:
                    future.result()
                
                # Быстрая очистка файлов прогресса
                for i in range(CONFIG['num_threads']):
                    try:
                        os.unlink(os.path.join(CONFIG['state_dir'], f"thread_{i}.progress"))
                    except:
                        pass
                
                # Оптимизированная очистка кешей
                optimized_clear_caches()
                
                # Умная сборка мусора
                if block_counter.get_count() % CONFIG['gc_collect_interval'] == 0:
                    gc.collect()
                
                time.sleep(CONFIG['block_delay'])
        
        finally:
            executor.shutdown(wait=False)
    
    except KeyboardInterrupt:
        logger.log(f"\n{Fore.YELLOW}Поиск остановлен пользователем.{Style.RESET_ALL}")
    except Exception as e:
        logger.log(f"\n{Fore.RED}Ошибка: {type(e).__name__}: {e}{Style.RESET_ALL}")
    finally:
        logger.log(f"\n{Fore.CYAN}Завершение работы...{Style.RESET_ALL}")
        if os.path.exists(CONFIG['state_dir']):
            shutil.rmtree(CONFIG['state_dir'])
        gc.enable()

if __name__ == "__main__":
    freeze_support()
    logger.log(f"{Fore.YELLOW}Запуск поиска...{Style.RESET_ALL}")
    main()
