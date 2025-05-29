# -*- coding: utf-8 -*-
import hashlib
import coincurve
from concurrent.futures import ProcessPoolExecutor
import time
import os
import json
import threading
from multiprocessing import freeze_support
from colorama import init, Fore, Back, Style
import sys
import signal
import random
from datetime import datetime
import shutil
import re
from typing import Dict, Tuple, List
from numba import njit
import numpy as np

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
    "state_file": "point_search_state.json",
    "backup_dir": "backups",
    "max_backups": 5,
    "update_interval": 1.0,
    "backup_interval": 300,
    "max_repeats": 4,
    "max_sequence": 4,
    "max_similar": 5,
    "min_key_length": 64
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
    """Проверяет валидность только последних 17 символов ключа"""
    if len(key_hex) != CONFIG['min_key_length']:
        return False
    
    if not re.match(r'^0{46}[4-7][0-9a-f]{17}$', key_hex):
        return False
    
    last_17 = key_hex[-17:]
    
    if re.search(r'(.)\1{' + str(CONFIG['max_repeats']) + r',}', last_17):
        return False
    
    # Используем Numba-ускоренную функцию для проверки последовательностей
    for i in range(len(last_17) - CONFIG['max_sequence']):
        chunk = last_17[i:i+CONFIG['max_sequence']+1]
        if is_sequence_numba(chunk):
            return False
    
    char_counts = {}
    for char in last_17:
        char_counts[char] = char_counts.get(char, 0) + 1
        if char_counts[char] > CONFIG['max_similar']:
            return False
    
    bad_patterns = [
        r'(\d)\1{4,}',
        r'([a-f])\1{4,}',
        r'12345|23456|34567|45678|56789',
        r'abcde|bcdef',
        r'00000|11111|22222|33333|44444|55555|66666|77777|88888|99999',
        r'aaaaa|bbbbb|ccccc|ddddd|eeeee|fffff',
        r'01234|12345|23456|34567|45678|56789|6789a|789ab|89abc|9abcd|abcde|bcdef',
        r'dead|beef|face|feed|cafe|babe'
    ]
    
    for pattern in bad_patterns:
        if re.search(pattern, last_17, re.IGNORECASE):
            return False
    
    return True

def generate_valid_random_key() -> Tuple[int, str]:
    """Генерирует случайный валидный ключ"""
    attempts = 0
    max_attempts = 10000
    
    while attempts < max_attempts:
        attempts += 1
        first_char = str(random.choice([4,5,6,7]))
        random_part = ''.join(random.choice('0123456789abcdef') for _ in range(17))
        key_hex = '0'*46 + first_char + random_part
        
        if is_valid_key(key_hex):
            key_int = int(key_hex, 16)
            if CONFIG['start_range'] <= key_int <= CONFIG['end_range']:
                return (key_int, key_hex)
    
    raise ValueError(f"Не удалось сгенерировать валидный ключ после {max_attempts} попыток")

def process_key(key_int: int, target_hash: str) -> Tuple[bool, str]:
    """Обрабатывает один ключ"""
    key_hex = "%064x" % key_int
    try:
        key_bytes = bytes.fromhex(key_hex)
        pub_key = coincurve.PublicKey.from_secret(key_bytes).format(compressed=True)
        h = hashlib.new('ripemd160', hashlib.sha256(pub_key).digest()).hexdigest()
        return (h == target_hash, key_hex)
    except:
        return (False, "")

def process_range(start_key: int, end_key: int, thread_id: int, progress_file: str):
    """Обрабатывает диапазон ключей и записывает прогресс в файл"""
    checked = 0
    start_time = time.time()
    
    try:
        for current in range(start_key, min(end_key, start_key + CONFIG['check_range']) + 1):
            found, key_hex = process_key(current, CONFIG['target_hash'])
            
            if found:
                with open(progress_file, 'a') as f:
                    f.write(f"FOUND {thread_id} {key_hex}\n")
                return
            
            checked += 1
            
            # Записываем прогресс каждые 10000 ключей
            if checked % 10000 == 0:
                with open(progress_file, 'a') as f:
                    f.write(f"PROGRESS {thread_id} {checked} {current}\n")
    
    except Exception as e:
        with open(progress_file, 'a') as f:
            f.write(f"ERROR {thread_id} {str(e)}\n")

def monitor_progress(progress_file: str, total_keys: int, num_threads: int):
    """Мониторит файл прогресса и выводит статус"""
    stats = {i: {'checked': 0, 'current': 0, 'speed': 0} for i in range(num_threads)}
    start_time = time.time()
    last_update = time.time()
    
    try:
        # Очищаем файл прогресса
        with open(progress_file, 'w') as f:
            pass
            
        while True:
            # Читаем новые строки из файла
            try:
                with open(progress_file, 'r') as f:
                    lines = f.readlines()
            except FileNotFoundError:
                time.sleep(0.1)
                continue
            
            # Обрабатываем каждую строку
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                    
                parts = line.split()
                if parts[0] == "FOUND":
                    logger.log(f"\n{Fore.GREEN}🎉 Найден ключ в потоке {parts[1]}: 0x{parts[2]}{Style.RESET_ALL}")
                    return True
                
                elif parts[0] == "PROGRESS":
                    thread_id = int(parts[1])
                    checked = int(parts[2])
                    current = int(parts[3])
                    stats[thread_id]['checked'] = checked
                    stats[thread_id]['current'] = current
                    stats[thread_id]['speed'] = checked / (time.time() - start_time + 0.0001)
                
                elif parts[0] == "ERROR":
                    logger.log(f"{Fore.RED}Ошибка в потоке {parts[1]}: {' '.join(parts[2:])}{Style.RESET_ALL}")
            
            # Выводим статус
            current_time = time.time()
            if current_time - last_update >= 1.0:
                print_status(stats, total_keys)
                last_update = current_time
            
            time.sleep(0.1)
            
    except KeyboardInterrupt:
        return False

def print_status(stats: Dict, total_keys: int):
    """Выводит красивый статус поиска"""
    total_checked = sum(s['checked'] for s in stats.values())
    completion = (total_checked / total_keys) * 100
    total_speed = sum(s['speed'] for s in stats.values())
    blocks_generated = block_counter.get_count()
    
    # Формируем строку статуса
    status_lines = [
        f"{Fore.CYAN}=== ПРОГРЕСС ПОИСКА ===",
        f"{Fore.YELLOW}Всего проверено:{Style.RESET_ALL} {total_checked:,}/{total_keys:,} ({completion:.2f}%)",
        f"{Fore.YELLOW}Скорость:{Style.RESET_ALL} {total_speed:,.0f} ключ/сек",
        f"{Fore.YELLOW}Сгенерировано блоков:{Style.RESET_ALL} {blocks_generated}",
        f"\n{Fore.YELLOW}СТАТУС ПОТОКОВ:{Style.RESET_ALL}"
    ]
    
    # Добавляем информацию по каждому потоку
    for tid in sorted(stats.keys()):
        s = stats[tid]
        status_lines.append(
            f"Поток {tid}: {s['checked']:,} ключей | "
            f"Скорость: {s['speed']:,.0f}/сек | "
            f"Текущий: 0x{s['current']:x}"
        )
    
    # Очищаем экран и выводим статус
    os.system('cls' if os.name == 'nt' else 'clear')
    logger.log('\n'.join(status_lines))

def test_hashing() -> bool:
    """Тестирование хеширования"""
    logger.log(f"\n{Fore.CYAN}=== ТЕСТ ХЕШИРОВАНИЯ ==={Style.RESET_ALL}")
    
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
    
    all_ok = True
    for test in test_vectors:
        try:
            key_bytes = bytes.fromhex(test['privkey'])
            pub_key = coincurve.PublicKey.from_secret(key_bytes).format(compressed=True)
            h = hashlib.new('ripemd160', hashlib.sha256(pub_key).digest()).hexdigest()
            
            if h == test['hash160']:
                logger.log(f"{Fore.GREEN}✓ Тест пройден для {test['privkey']}{Style.RESET_ALL}")
            else:
                logger.log(f"{Fore.RED}✗ Ошибка для {test['privkey']}{Style.RESET_ALL}")
                logger.log(f"  Ожидалось: {test['hash160']}")
                logger.log(f"  Получено:  {h}")
                all_ok = False
        except Exception as e:
            logger.log(f"{Fore.RED}✗ Ошибка теста для {test['privkey']}: {e}{Style.RESET_ALL}")
            all_ok = False
    
    return all_ok

def main():
    """Основная функция программы"""
    logger.log(f"{Fore.GREEN}Инициализация программы...{Style.RESET_ALL}")
    
    if not test_hashing():
        logger.log(f"{Fore.RED}Тест хеширования не пройден, работа прервана.{Style.RESET_ALL}")
        return
    
    logger.log(f"{Fore.GREEN}Тесты пройдены успешно! Запускаем поиск...{Style.RESET_ALL}")
    
    try:
        progress_file = "search_progress.txt"
        total_keys = CONFIG['check_range']
        
        # Запускаем монитор прогресса в отдельном потоке
        monitor_thread = threading.Thread(
            target=monitor_progress,
            args=(progress_file, total_keys, CONFIG['num_threads'])
        )
        monitor_thread.daemon = True
        monitor_thread.start()
        
        # Даем монитору время запуститься
        time.sleep(1)
        
        # Запускаем worker-процессы
        with ProcessPoolExecutor(max_workers=CONFIG['num_threads']) as executor:
            while True:
                start_key, current_key_hex = generate_valid_random_key()
                block_counter.increment()
                logger.log(f"\n{Fore.CYAN}Новый блок начат: 0x{current_key_hex} (Всего блоков: {block_counter.get_count()}){Style.RESET_ALL}")
                
                # Распределяем диапазоны по потокам
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
                        i,
                        progress_file
                    ))
                
                # Ожидаем завершения всех потоков
                for future in futures:
                    future.result()
                
                logger.log(f"{Fore.GREEN}Блок завершен! Всего блоков: {block_counter.get_count()}{Style.RESET_ALL}")
    
    except KeyboardInterrupt:
        logger.log(f"\n{Fore.YELLOW}Поиск остановлен пользователем.{Style.RESET_ALL}")
    except Exception as e:
        logger.log(f"\n{Fore.RED}Критическая ошибка: {str(e)}{Style.RESET_ALL}")
    finally:
        logger.log(f"{Fore.CYAN}Программа завершена.{Style.RESET_ALL}")

if __name__ == "__main__":
    freeze_support()
    logger.log(f"{Fore.YELLOW}Запуск программы...{Style.RESET_ALL}")
    main()
