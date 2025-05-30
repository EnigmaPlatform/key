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
from typing import Dict, Tuple, List, Optional
from queue import Queue, Empty
import ctypes
import shutil

# Инициализация colorama
init(autoreset=True)

# Конфигурация
CONFIG = {
    "target_hash": "f6f5431d25bbf7b12e8add9af5e3475c44a0a5b8",
    "start_range": 0x400000000000000000,
    "end_range": 0x7fffffffffffffffff,
    "num_threads": 12,
    "check_range": 250_000_000,
    "chunk_size": 20_900_000,
    "max_attempts": 1_000_000,
    "state_dir": "progress_states",
    "update_interval": 1.0,
    "max_repeats": 4,
    "max_sequence": 4,
    "max_similar": 5,
    "min_key_length": 64,
    "progress_queue_size": 1000,
    "cache_clear_threshold": 100_000
}

class ProgressQueue:
    def __init__(self):
        self.queue = Queue(maxsize=CONFIG['progress_queue_size'])
        self._stop_event = threading.Event()
        self.writer_thread = threading.Thread(target=self._writer, daemon=True)
        self.writer_thread.start()
    
    def put(self, thread_id: int, message: str):
        try:
            self.queue.put_nowait((thread_id, message))
        except:
            pass
    
    def _writer(self):
        while not self._stop_event.is_set():
            try:
                thread_id, message = self.queue.get(timeout=0.5)
                progress_file = os.path.join(CONFIG['state_dir'], f"thread_{thread_id}.progress")
                with open(progress_file, 'a') as f:
                    f.write(message + "\n")
            except Empty:
                continue
            except:
                pass
    
    def stop(self):
        self._stop_event.set()
        self.writer_thread.join()

progress_queue = ProgressQueue()

class LightLogger:
    def __init__(self):
        self.lock = threading.Lock()
        self.last_output_time = 0
        self.output_interval = 0.1
        self.buffer = []
    
    def log(self, message: str, force: bool = False):
        with self.lock:
            current_time = time.time()
            if force or (current_time - self.last_output_time >= self.output_interval):
                sys.stdout.write(message + "\n")
                sys.stdout.flush()
                self.last_output_time = current_time
                self.buffer = []
            else:
                self.buffer.append(message)
    
    def flush(self):
        with self.lock:
            if self.buffer:
                sys.stdout.write("\n".join(self.buffer) + "\n")
                sys.stdout.flush()
                self.buffer = []

logger = LightLogger()

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

def is_valid_key(key_hex: str) -> bool:
    """Проверка валидности ключа"""
    if len(key_hex) != 64:
        return False
    
    # Проверка префикса
    for i in range(46):
        if key_hex[i] != '0':
            return False
    
    if key_hex[46] not in {'4', '5', '6', '7'}:
        return False
    
    last_17 = key_hex[-17:]
    
    # Проверка запрещенных последовательностей
    for i in range(len(last_17) - 4):
        if (last_17[i] == last_17[i+1] == last_17[i+2] == last_17[i+3] == last_17[i+4]):
            return False
    
    return True

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

def test_hashing() -> bool:
    """Тест хеширования перед запуском"""
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
    
    logger.log(f"{Fore.CYAN}\n=== ТЕСТ ХЕШИРОВАНИЯ ===", True)
    logger.log(f"Проверка корректности работы алгоритмов...", True)
    
    all_passed = True
    for test in test_vectors:
        try:
            key_bytes = bytes.fromhex(test['privkey'])
            pub_key = coincurve.PublicKey.from_secret(key_bytes).format(compressed=True)
            pub_key_hash = hashlib.sha256(pub_key).digest()
            h = hashlib.new('ripemd160', pub_key_hash).hexdigest()
            
            if h == test['hash160']:
                logger.log(f"{Fore.GREEN}✓ {test['name']} - OK{Style.RESET_ALL}", True)
            else:
                logger.log(f"{Fore.RED}✗ {test['name']} - Ошибка{Style.RESET_ALL}", True)
                all_passed = False
        except Exception as e:
            logger.log(f"{Fore.RED}✗ {test['name']} - Ошибка: {e}{Style.RESET_ALL}", True)
            all_passed = False
    
    if all_passed:
        logger.log(f"{Fore.GREEN}Тест хеширования успешно пройден!{Style.RESET_ALL}", True)
    else:
        logger.log(f"{Fore.RED}Тест хеширования не пройден!{Style.RESET_ALL}", True)
    
    return all_passed

def process_key(key_int: int) -> Tuple[bool, str]:
    """Обработка ключа с проверкой хеша"""
    try:
        key_hex = "%064x" % key_int
        key_bytes = bytes.fromhex(key_hex)
        pub_key = coincurve.PublicKey.from_secret(key_bytes).format(compressed=True)
        pub_key_hash = hashlib.sha256(pub_key).digest()
        h = hashlib.new('ripemd160', pub_key_hash).hexdigest()
        
        return (h == CONFIG['target_hash'], key_hex)
    except Exception as e:
        return (False, "")

def process_range(start_key: int, end_key: int, thread_id: int):
    """Обработка диапазона ключей"""
    progress_queue.put(thread_id, f"START {start_key} {end_key}")
    current = start_key
    last_report = current
    
    try:
        # Проверяем только первый ключ на валидность
        if thread_id == 0:
            key_hex = "%064x" % start_key
            if not is_valid_key(key_hex):
                progress_queue.put(thread_id, f"ERROR Стартовый ключ невалиден: {key_hex}")
                return

        while current <= end_key:
            found, key_hex = process_key(current)
            if found:
                progress_queue.put(thread_id, f"FOUND {key_hex}")
                return
            
            current += 1
            
            if current - last_report >= CONFIG['cache_clear_threshold']:
                progress_queue.put(thread_id, f"PROGRESS {current}")
                last_report = current
    
    except Exception as e:
        progress_queue.put(thread_id, f"ERROR {str(e)}")
    finally:
        progress_queue.put(thread_id, f"END {current - start_key}")

def light_progress_bar(iteration, total, length=30):
    """Упрощенный прогресс-бар"""
    if total <= 0:
        return "[------]"
    
    percent = min(100, (iteration / total) * 100)
    filled = min(length, int(length * iteration // total))
    return f"[{'#' * filled}{'-' * (length - filled)}] {percent:.1f}%"

def monitor_progress(total_keys: int, num_threads: int):
    """Мониторинг прогресса"""
    stats = {i: {'current': 0, 'start': 0, 'end': 0} for i in range(num_threads)}
    start_time = time.time()
    last_update = time.time()
    
    try:
        os.makedirs(CONFIG['state_dir'], exist_ok=True)
        found = False
        
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
                            logger.log(f"\n{Fore.GREEN}Найден ключ: 0x{parts[1]}{Style.RESET_ALL}", True)
                            return True
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
                    logger.log(f"{Fore.YELLOW}Ошибка чтения файла прогресса: {e}{Style.RESET_ALL}", True)
                    continue
            
            current_time = time.time()
            if current_time - last_update >= CONFIG['update_interval']:
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
                        elapsed_time = max(0.1, current_time - start_time)
                        speed = completed / elapsed_time
                        
                        sys.stdout.write("\r")
                        sys.stdout.write(f"Прогресс: {light_progress_bar(completed, total_range)} ")
                        sys.stdout.write(f"Скорость: {speed/1000:,.1f}K keys/s ")
                        sys.stdout.flush()
                    
                    last_update = current_time
                except Exception as e:
                    logger.log(f"{Fore.RED}Ошибка обновления прогресса: {e}{Style.RESET_ALL}", True)
                    time.sleep(1)
            
            time.sleep(0.1)
                
    except KeyboardInterrupt:
        return False
    except Exception as e:
        logger.log(f"{Fore.RED}Критическая ошибка в мониторе: {e}{Style.RESET_ALL}", True)
        return False
    finally:
        sys.stdout.write("\n")
        sys.stdout.flush()
    
    return False

def main():
    """Основная функция"""
    logger.log(f"{Fore.CYAN}=== ИНИЦИАЛИЗАЦИЯ ПРОГРАММЫ ===", True)
    
    # Проверка теста хеширования перед запуском
    if not test_hashing():
        logger.log(f"\n{Fore.RED}Тест хеширования не пройден! Завершение работы.{Style.RESET_ALL}", True)
        return
    
    if os.path.exists(CONFIG['state_dir']):
        shutil.rmtree(CONFIG['state_dir'])
    
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
        
        # Генерация и проверка стартового ключа
        start_key, start_key_hex = generate_valid_random_key()
        logger.log(f"\n{Fore.MAGENTA}Начало работы с ключа: 0x{start_key_hex}{Style.RESET_ALL}", True)
        
        # Запуск обработки
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
        
        # Ожидание завершения
        for future in futures:
            future.result()
        
        logger.log(f"\n{Fore.YELLOW}Завершено сканирование заданного диапазона.{Style.RESET_ALL}", True)
        
    except KeyboardInterrupt:
        logger.log(f"\n{Fore.YELLOW}Поиск остановлен пользователем.{Style.RESET_ALL}", True)
    except Exception as e:
        logger.log(f"\n{Fore.RED}Ошибка: {type(e).__name__}: {e}{Style.RESET_ALL}", True)
    finally:
        executor.shutdown(wait=False)
        progress_queue.stop()
        logger.log(f"\n{Fore.CYAN}=== ЗАВЕРШЕНИЕ РАБОТЫ ==={Style.RESET_ALL}", True)
        if os.path.exists(CONFIG['state_dir']):
            shutil.rmtree(CONFIG['state_dir'])
        logger.flush()

if __name__ == "__main__":
    freeze_support()
    logger.log(f"{Fore.YELLOW}=== ЗАПУСК ПРОГРАММЫ ==={Style.RESET_ALL}", True)
    main()
