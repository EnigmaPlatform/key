# -*- coding: utf-8 -*-
import hashlib
import coincurve
from concurrent.futures import ProcessPoolExecutor, as_completed
import time
import sys
import os
import random
from numba import jit
import traceback
from multiprocessing import Manager, freeze_support
from colorama import init, Fore, Back, Style
import platform

# Инициализация colorama
init()

# Конфигурация
TEST_KEY = "0000000000000000000000000000000000000000000000000000000000000001"
TEST_HASH = "751e76e8199196d454941c45d1b3a323f1433bd6"
TARGET_HASH = "f6f5431d25bbf7b12e8add9af5e3475c44a0a5b8"
START_RANGE = 0x600000000000000000
END_RANGE = 0x800000000000000000
NUM_THREADS = 12

# Настройки производительности
MIN_UPDATE_INTERVAL = 2.0
PROGRESS_UPDATE_ITERATIONS = 1000

@jit(nopython=True)
def should_skip_key_numba(key_hex):
    last_17 = key_hex[-17:]
    
    # Проверка на 4+ повторяющихся символа
    count = 1
    prev = last_17[0]
    for c in last_17[1:]:
        if c == prev:
            count += 1
            if count >= 4:
                return True
        else:
            count = 1
            prev = c
    
    # Проверка на 5+ цифр или букв подряд
    seq_len = 1
    for i in range(1, len(last_17)):
        if (last_17[i].isdigit() and last_17[i-1].isdigit()) or \
           (last_17[i].islower() and last_17[i-1].islower()):
            seq_len += 1
            if seq_len >= 5:
                return True
        else:
            seq_len = 1
    
    # Проверка на все цифры или все буквы
    all_digits = True
    all_letters = True
    for c in last_17:
        if not c.isdigit():
            all_digits = False
        if not c.islower():
            all_letters = False
        if not all_digits and not all_letters:
            break
    
    return all_digits or all_letters

def should_skip_key(key_hex):
    try:
        return should_skip_key_numba(key_hex)
    except Exception as e:
        print(f"{Fore.RED}Ошибка в should_skip_key: {str(e)}{Style.RESET_ALL}")
        return False

def run_tests():
    print(f"\n{Fore.YELLOW}=== ТЕСТИРОВАНИЕ ===")
    print(f"{Fore.YELLOW}🔹 Запуск тестов...{Style.RESET_ALL}")
    
    # Тест хеширования
    try:
        key_bytes = bytes.fromhex(TEST_KEY)
        pub_key = coincurve.PublicKey.from_secret(key_bytes).format(compressed=True)
        sha256 = hashlib.sha256(pub_key).digest()
        ripemd160 = hashlib.new('ripemd160', sha256).hexdigest()
        assert ripemd160 == TEST_HASH
        print(f"{Fore.GREEN}✅ Тест хеширования пройден{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}❌ Ошибка теста хеширования: {str(e)}{Style.RESET_ALL}")
        traceback.print_exc()
        return False
    
    # Тест фильтрации
    test_cases = [
        ("0000000000000000000000000000000000000000000000000000000000000000", True),
        ("abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd", True),
        ("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a", False)
    ]
    
    try:
        for i, (key, expected) in enumerate(test_cases, 1):
            result = should_skip_key(key)
            if result != expected:
                print(f"{Fore.RED}❌ Тест фильтрации {i} не пройден для ключа {key}: ожидалось {expected}, получено {result}{Style.RESET_ALL}")
                return False
        
        print(f"{Fore.GREEN}✅ Тест фильтрации пройден{Style.RESET_ALL}")
        return True
    except Exception as e:
        print(f"{Fore.RED}❌ Критическая ошибка в тесте фильтрации: {str(e)}{Style.RESET_ALL}")
        traceback.print_exc()
        return False

def benchmark():
    print(f"\n{Fore.YELLOW}=== БЕНЧМАРК ===")
    print(f"{Fore.YELLOW}🔹 Тестирование производительности...{Style.RESET_ALL}")
    test_keys = [''.join(random.choice('0123456789abcdef') for _ in range(64)) 
                for _ in range(10000)]
    
    start = time.time()
    for key in test_keys:
        should_skip_key(key)
    
    elapsed = time.time() - start
    speed = len(test_keys) / elapsed
    print(f"{Fore.CYAN}Обработано {len(test_keys):,} ключей за {elapsed:.2f} секунд{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Скорость: {speed:,.0f} ключей/сек{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}================={Style.RESET_ALL}\n")
    return True

def process_range(thread_id, range_start, range_end, result_queue):
    try:
        current = range_start
        processed = 0
        skipped = 0
        last_speed_update = time.time()
        processed_since_update = 0
        
        while current <= range_end:
            key_hex = f"{current:064x}"
            
            if not should_skip_key(key_hex):
                try:
                    pub_key = coincurve.PublicKey.from_secret(bytes.fromhex(key_hex)).format(compressed=True)
                    h = hashlib.new('ripemd160', hashlib.sha256(pub_key).digest()).hexdigest()
                    
                    if h == TARGET_HASH:
                        result_queue.put(('found', key_hex))
                        return
                    
                    processed += 1
                    processed_since_update += 1
                except Exception as e:
                    skipped += 1
            else:
                skipped += 1
            
            if current % PROGRESS_UPDATE_ITERATIONS == 0:
                speed = processed_since_update / (time.time() - last_speed_update) if (time.time() - last_speed_update) > 0 else 0
                result_queue.put(('progress', {
                    'thread_id': thread_id,
                    'current': current,
                    'processed': processed,
                    'skipped': skipped,
                    'speed': speed
                }))
                processed_since_update = 0
                last_speed_update = time.time()
            
            current += 1
        
        result_queue.put(('done', thread_id))
    except Exception as e:
        result_queue.put(('error', str(e)))

def print_progress(progress_data):
    os.system('cls' if os.name == 'nt' else 'clear')
    
    # Выводим заголовок и тестовую информацию
    print(f"{Fore.YELLOW}=== ИНФОРМАЦИЯ О СИСТЕМЕ ===")
    print(f"Запуск на {platform.system()} с Python {sys.version.split()[0]}")
    print(f"Диапазон: 0x{START_RANGE:016x} - 0x{END_RANGE:016x}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}======================={Style.RESET_ALL}\n")
    
    # Выводим прогресс по потокам
    print(f"{Fore.CYAN}=== ПРОГРЕСС ПОИСКА ({NUM_THREADS} потоков) ==={Style.RESET_ALL}")
    for tid in sorted(progress_data.keys()):
        data = progress_data[tid]
        key_hex = f"{data['current']:064x}"
        last_key_display = f"0x...{key_hex[-18:]}" if len(key_hex) >= 18 else "0x...{key_hex}"
        
        status = f"{Fore.GREEN}Активен" if data['active'] else f"{Fore.RED}Завершен"
        
        print(
            f"{Fore.WHITE}Поток {tid:2}: {status}{Style.RESET_ALL} | "
            f"Обработано: {Fore.GREEN}{data['processed']:7,}{Style.RESET_ALL} | "
            f"Пропущено: {Fore.YELLOW}{data['skipped']:7,}{Style.RESET_ALL} | "
            f"Скорость: {Fore.CYAN}{data.get('speed', 0):7,.0f}/s{Style.RESET_ALL} | "
            f"Текущий: {Fore.MAGENTA}{last_key_display}{Style.RESET_ALL}"
        )
    
    print(f"\n{Fore.YELLOW}Для выхода нажмите Ctrl+C{Style.RESET_ALL}")

def main():
    # Запускаем тесты и бенчмарк
    if not run_tests():
        return
    
    if not benchmark():
        return
    
    # Инициализация многопроцессорных структур
    manager = Manager()
    result_queue = manager.Queue()
    
    # Вычисляем диапазоны для каждого потока
    total = END_RANGE - START_RANGE
    chunk = total // NUM_THREADS
    ranges = [(i, START_RANGE + i * chunk, 
               START_RANGE + (i + 1) * chunk - 1 if i < NUM_THREADS - 1 else END_RANGE) 
              for i in range(NUM_THREADS)]
    
    # Инициализируем данные для отображения прогресса
    progress_data = {
        tid: {
            'current': start,
            'processed': 0,
            'skipped': 0,
            'speed': 0,
            'active': True
        } for tid, start, _ in ranges
    }
    
    print(f"\n{Fore.YELLOW}🔹 Начало поиска с {NUM_THREADS} потоками...{Style.RESET_ALL}")
    time.sleep(2)  # Даем время прочитать предыдущие сообщения
    
    try:
        with ProcessPoolExecutor(max_workers=NUM_THREADS) as executor:
            # Запускаем потоки
            futures = [executor.submit(process_range, tid, start, end, result_queue) 
                      for tid, start, end in ranges]
            
            active_threads = NUM_THREADS
            last_update_time = 0
            
            while active_threads > 0:
                # Обрабатываем сообщения из очереди
                while not result_queue.empty():
                    msg_type, data = result_queue.get_nowait()
                    
                    if msg_type == 'found':
                        print(f"\n{Fore.GREEN}🎉 КЛЮЧ НАЙДЕН: 0x{data}{Style.RESET_ALL}")
                        for tid in progress_data:
                            progress_data[tid]['active'] = False
                        return
                        
                    elif msg_type == 'progress':
                        tid = data['thread_id']
                        progress_data[tid].update({
                            'current': data['current'],
                            'processed': data['processed'],
                            'skipped': data['skipped'],
                            'speed': data['speed']
                        })
                        
                    elif msg_type == 'done':
                        progress_data[data]['active'] = False
                        active_threads -= 1
                        
                    elif msg_type == 'error':
                        print(f"{Fore.RED}❌ Ошибка в потоке: {data}{Style.RESET_ALL}")
                
                # Обновляем экран каждые MIN_UPDATE_INTERVAL секунд
                if time.time() - last_update_time >= MIN_UPDATE_INTERVAL:
                    print_progress(progress_data)
                    last_update_time = time.time()
                
                time.sleep(0.1)
            
            print_progress(progress_data)
            print(f"\n{Fore.YELLOW}🔹 Поиск завершен, ключ не найден{Style.RESET_ALL}")
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}🛑 Поиск остановлен пользователем{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}❌ Критическая ошибка: {str(e)}{Style.RESET_ALL}")
        traceback.print_exc()

if __name__ == "__main__":
    freeze_support()
    try:
        main()
    except Exception as e:
        print(f"\n{Fore.RED}❌ Необработанная ошибка: {str(e)}{Style.RESET_ALL}")
        traceback.print_exc()
