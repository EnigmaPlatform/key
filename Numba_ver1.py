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
import shutil  # Добавлен недостающий импорт

# Инициализация colorama
init(autoreset=True)

# Конфигурация
CONFIG = {
    "target_hash": "f6f5431d25bbf7b12e8add9af5e3475c44a0a5b8",
    "start_range": 0x400000000000000000,
    "end_range": 0x7fffffffffffffffff,
    "num_threads": 12,
    "check_range": 100_000_000,
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
    "gc_interval": 100_000,  # Интервал для сборки мусора
    "block_delay": 0.5  # Задержка между блоками в секундах
}

class BlockCounter:
    def __init__(self):
        self.count = 0
        self.lock = threading.Lock()
    
    def increment(self):
        with self.lock:
            self.count += 1
    
    def get_count(self):
        with self.lock:
            return self.count

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
    # Уменьшаем приоритет процесса для стабильности системы
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
    """Проверяет последовательности символов с использованием Numba"""
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
    """Оптимизированная проверка валидности ключа"""
    if len(key_hex) != CONFIG['min_key_length']:
        return False
    
    if not key_hex.startswith('0'*46) or key_hex[46] not in '4567':
        return False
    
    last_17 = key_hex[-17:]
    
    # Быстрые проверки перед сложными
    if ('11111' in last_17 or 'aaaaa' in last_17 or 
        '22222' in last_17 or 'bbbbb' in last_17):
        return False
    
    # Проверка повторяющихся символов
    for i in range(len(last_17) - CONFIG['max_repeats']):
        if len(set(last_17[i:i+CONFIG['max_repeats']+1])) == 1:
            return False
    
    # Проверка последовательностей
    for i in range(len(last_17) - CONFIG['max_sequence']):
        chunk = last_17[i:i+CONFIG['max_sequence']+1]
        if is_sequence_numba(chunk):
            return False
    
    return True

def generate_valid_random_key() -> Tuple[int, str]:
    """Генерация ключей с использованием secrets для криптографической безопасности"""
    chars = '0123456789abcdef'
    first_chars = '4567'
    
    for _ in range(10_000):
        # Используем secrets вместо random
        first_char = secrets.choice(first_chars)
        random_part = ''.join(secrets.choice(chars) for _ in range(17))
        key_hex = '0'*46 + first_char + random_part
        
        if is_valid_key(key_hex):
            key_int = int(key_hex, 16)
            if CONFIG['start_range'] <= key_int <= CONFIG['end_range']:
                return (key_int, key_hex)
    
    raise ValueError("Не удалось сгенерировать валидный ключ")

def process_key(key_int: int, target_hash: str) -> Tuple[bool, str]:
    """Обработка ключа с контролем памяти"""
    key_hex = "%064x" % key_int
    try:
        # Явное освобождение памяти после использования
        key_bytes = bytes.fromhex(key_hex)
        pub_key = coincurve.PublicKey.from_secret(key_bytes).format(compressed=True)
        pub_key_hash = hashlib.sha256(pub_key).digest()
        h = hashlib.new('ripemd160', pub_key_hash).hexdigest()
        
        # Очищаем временные переменные
        del key_bytes, pub_key, pub_key_hash
        return (h == target_hash, key_hex)
    except Exception as e:
        logger.log(f"{Fore.RED}Ошибка обработки ключа: {e}{Style.RESET_ALL}")
        return (False, "")

def process_range(start_key: int, end_key: int, thread_id: int):
    """Обработка диапазона ключей с индивидуальным файлом прогресса"""
    progress_file = os.path.join(CONFIG['state_dir'], f"thread_{thread_id}.progress")
    checked = 0
    last_gc = 0
    
    try:
        os.makedirs(CONFIG['state_dir'], exist_ok=True)
        
        for current in range(start_key, min(end_key, start_key + CONFIG['check_range']) + 1):
            found, key_hex = process_key(current, CONFIG['target_hash'])
            
            if found:
                with open(progress_file, 'a') as f:
                    f.write(f"FOUND {key_hex}\n")
                return
            
            checked += 1
            
            # Периодическая запись прогресса и очистка памяти
            if checked % 10_000 == 0:
                with open(progress_file, 'a') as f:
                    f.write(f"PROGRESS {checked} {current}\n")
                
                if checked - last_gc >= CONFIG['gc_interval']:
                    gc.collect()
                    last_gc = checked
    
    except Exception as e:
        with open(progress_file, 'a') as f:
            f.write(f"ERROR {str(e)}\n")
    finally:
        # Финализация - гарантированная запись прогресса
        with open(progress_file, 'a') as f:
            f.write(f"COMPLETED {checked} {start_key} {end_key}\n")

def monitor_progress(total_keys: int, num_threads: int):
    """Мониторинг прогресса с индивидуальными файлами потоков"""
    stats = {i: {'checked': 0, 'current': 0, 'speed': 0} for i in range(num_threads)}
    start_time = time.time()
    
    try:
        os.makedirs(CONFIG['state_dir'], exist_ok=True)
        
        while True:
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
                            logger.log(f"\n{Fore.GREEN}🎉 Найден ключ в потоке {thread_id}: 0x{parts[1]}{Style.RESET_ALL}")
                            return True
                        
                        elif parts[0] == "PROGRESS":
                            stats[thread_id]['checked'] = int(parts[1])
                            stats[thread_id]['current'] = int(parts[2])
                            stats[thread_id]['speed'] = stats[thread_id]['checked'] / (time.time() - start_time + 0.0001)
                            any_active = True
                        
                        elif parts[0] == "ERROR":
                            logger.log(f"{Fore.RED}Ошибка в потоке {thread_id}: {' '.join(parts[1:])}{Style.RESET_ALL}")
                
                except FileNotFoundError:
                    continue
            
            # Вывод статуса
            print_status(stats, total_keys)
            
            if not any_active:
                time.sleep(0.5)
            else:
                time.sleep(1)
                
    except KeyboardInterrupt:
        return False

def print_status(stats: Dict, total_keys: int):
    """Улучшенный вывод статуса с информацией о памяти"""
    total_checked = sum(s['checked'] for s in stats.values())
    completion = (total_checked / total_keys) * 100
    total_speed = sum(s['speed'] for s in stats.values())
    blocks_generated = block_counter.get_count()
    
    # Информация об использовании памяти
    try:
        import psutil
        mem = psutil.virtual_memory()
        mem_info = f"{mem.used/1024/1024:.1f}MB/{mem.total/1024/1024:.1f}MB ({mem.percent}%)"
    except:
        mem_info = "N/A"
    
    status_lines = [
        f"{Fore.CYAN}=== ПРОГРЕСС ПОИСКА ===",
        f"{Fore.YELLOW}Всего проверено:{Style.RESET_ALL} {total_checked:,}/{total_keys:,} ({completion:.2f}%)",
        f"{Fore.YELLOW}Скорость:{Style.RESET_ALL} {total_speed:,.0f} ключ/сек",
        f"{Fore.YELLOW}Сгенерировано блоков:{Style.RESET_ALL} {blocks_generated}",
        f"{Fore.YELLOW}Использование памяти:{Style.RESET_ALL} {mem_info}",
        f"\n{Fore.YELLOW}СТАТУС ПОТОКОВ:{Style.RESET_ALL}"
    ]
    
    for tid in sorted(stats.keys()):
        s = stats[tid]
        status_lines.append(
            f"Поток {tid}: {s['checked']:,} ключей | "
            f"Скорость: {s['speed']:,.0f}/сек | "
            f"Текущий: 0x{s['current']:x}"
        )
    
    os.system('cls' if os.name == 'nt' else 'clear')
    logger.log('\n'.join(status_lines))

def test_hashing() -> bool:
    """Тестирование хеширования с контролем памяти"""
    test_vectors = [
        {
            'privkey': '0000000000000000000000000000000000000000000000000000000000000001',
            'hash160': '751e76e8199196d454941c45d1b3a323f1433bd6'
        },
        {
            'privkey': 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140',
            'hash160': 'adde4c73c7b9cee17da6c7b3e2b2eea1a0dcbe67'
        }
    ]
    
    for test in test_vectors:
        try:
            key_bytes = bytes.fromhex(test['privkey'])
            pub_key = coincurve.PublicKey.from_secret(key_bytes).format(compressed=True)
            pub_key_hash = hashlib.sha256(pub_key).digest()
            h = hashlib.new('ripemd160', pub_key_hash).hexdigest()
            
            if h != test['hash160']:
                return False
            
            # Принудительная очистка
            del key_bytes, pub_key, pub_key_hash
            gc.collect()
        except:
            return False
    return True

def main():
    """Основная функция с улучшенным управлением ресурсами"""
    logger.log(f"{Fore.GREEN}Инициализация программы...{Style.RESET_ALL}")
    
    # Проверка тестов
    if not test_hashing():
        logger.log(f"{Fore.RED}Тест хеширования не пройден!{Style.RESET_ALL}")
        return
    
    # Очистка предыдущих состояний
    if os.path.exists(CONFIG['state_dir']):
        shutil.rmtree(CONFIG['state_dir'])
    
    try:
        total_keys = CONFIG['check_range']
        
        # Монитор прогресса
        monitor_thread = threading.Thread(
            target=monitor_progress,
            args=(total_keys, CONFIG['num_threads']),
            daemon=True
        )
        monitor_thread.start()
        time.sleep(1)
        
        # Основной цикл обработки
        with ProcessPoolExecutor(
            max_workers=CONFIG['num_threads'],
            initializer=init_worker
        ) as executor:
            while True:
                start_key, current_key_hex = generate_valid_random_key()
                block_counter.increment()
                
                logger.log(f"\n{Fore.CYAN}Блок {block_counter.get_count()}: 0x{current_key_hex}{Style.RESET_ALL}")
                
                # Распределение задач
                chunk_size = total_keys // CONFIG['num_threads']
                futures = []
                
                for i in range(CONFIG['num_threads']):
                    chunk_start = start_key + i * chunk_size
                    chunk_end = chunk_start + chunk_size - 1
                    
                    if i == CONFIG['num_threads'] - 1:
                        chunk_end = start_key + total_keys - 1
                    
                    futures.append(executor.submit(
                        process_range,
                        chunk_start,
                        chunk_end,
                        i
                    ))
                
                # Ожидание завершения
                for future in futures:
                    future.result()
                
                # Пауза между блоками
                time.sleep(CONFIG['block_delay'])
                
                # Принудительная очистка памяти
                gc.collect()
    
    except KeyboardInterrupt:
        logger.log(f"\n{Fore.YELLOW}Остановлено пользователем.{Style.RESET_ALL}")
    except Exception as e:
        logger.log(f"\n{Fore.RED}Ошибка: {type(e).__name__}: {e}{Style.RESET_ALL}")
    finally:
        logger.log(f"{Fore.CYAN}Завершение работы...{Style.RESET_ALL}")
        if os.path.exists(CONFIG['state_dir']):
            shutil.rmtree(CONFIG['state_dir'])

if __name__ == "__main__":
    freeze_support()
    logger.log(f"{Fore.YELLOW}Запуск поиска...{Style.RESET_ALL}")
    main()
