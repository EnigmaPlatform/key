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
MIN_UPDATE_INTERVAL = 2.0
PROGRESS_UPDATE_ITERATIONS = 1000

# Паттерны для пропуска
REPEAT_PATTERNS = ['aaaa', '5555', '0000', 'ffff', 'cccc']
SEQUENTIAL_PATTERNS = ['0123', '1234', 'abcd', 'bcde']

# ==================== ОСНОВНЫЕ ФУНКЦИИ ====================

@jit(nopython=True)
def has_quick_skip_pattern(key_hex):
    """Быстрая проверка очевидных паттернов с использованием Numba"""
    last_12 = key_hex[-12:]
    
    # Проверка 4+ повторяющихся символов
    for i in range(len(last_12)-3):
        if last_12[i] == last_12[i+1] == last_12[i+2] == last_12[i+3]:
            return True
    
    # Проверка последовательностей
    for i in range(len(last_12)-3):
        chunk = last_12[i:i+4]
        if chunk.isdigit():
            valid = True
            for j in range(3):
                if ord(chunk[j+1]) != ord(chunk[j]) + 1:
                    valid = False
                    break
            if valid:
                return True
        elif chunk.islower():
            valid = True
            for j in range(3):
                if ord(chunk[j+1]) != ord(chunk[j]) + 1:
                    valid = False
                    break
            if valid:
                return True
    
    return False

def calculate_jump(key_hex):
    """Вычисляет безопасный прыжок через невалидные диапазоны"""
    original = int(key_hex, 16)
    last_17 = key_hex[-17:]
    
    max_pattern_len = 0
    jump_pos = len(last_17)
    
    # Проверка известных паттернов
    for pattern in REPEAT_PATTERNS:
        pos = last_17.find(pattern)
        if pos != -1 and len(pattern) > max_pattern_len:
            max_pattern_len = len(pattern)
            jump_pos = pos
    
    for pattern in SEQUENTIAL_PATTERNS:
        pos = last_17.find(pattern)
        if pos != -1 and len(pattern) > max_pattern_len:
            max_pattern_len = len(pattern)
            jump_pos = pos
    
    if max_pattern_len >= 4:
        jump_value = 16 ** (16 - jump_pos)
        # Ограничиваем максимальный прыжок
        return min(original + min(jump_value, 0x100000), END_RANGE)
    
    # Дополнительные проверки
    for i in range(len(last_17)-4):
        chunk = last_17[i:i+5]
        if chunk.isdigit() or chunk.islower():
            return original + (16 ** (16 - i)) // 2
    
    return original + 1

def should_skip_key(key_hex):
    """Комбинированная проверка валидности ключа"""
    if has_quick_skip_pattern(key_hex):
        return True
    
    last_17 = key_hex[-17:]
    
    # Проверка на все цифры/буквы
    if last_17.isdigit() or last_17.islower():
        return True
    
    # Проверка на 5+ одинаковых символов
    for i in range(len(last_17)-4):
        if last_17[i] == last_17[i+1] == last_17[i+2] == last_17[i+3] == last_17[i+4]:
            return True
    
    return False

# ==================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ====================

def run_tests():
    """Запуск тестовых проверок"""
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
        ("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a", True)
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
    """Тестирование производительности"""
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

def print_progress(progress_data):
    """Вывод информации о прогрессе"""
    os.system('cls' if os.name == 'nt' else 'clear')
    
    print(f"{Fore.YELLOW}=== ИНФОРМАЦИЯ О СИСТЕМЕ ===")
    print(f"Запуск на {platform.system()} с Python {sys.version.split()[0]}")
    print(f"Диапазон: 0x{START_RANGE:016x} - 0x{END_RANGE:016x}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}======================={Style.RESET_ALL}\n")
    
    print(f"{Fore.CYAN}=== ПРОГРЕСС ПОИСКА ({NUM_THREADS} потоков) ==={Style.RESET_ALL}")
    for tid in sorted(progress_data.keys()):
        data = progress_data[tid]
        key_hex = f"{data['current']:064x}"
        last_key_display = f"0x...{key_hex[-18:]}" if len(key_hex) >= 18 else f"0x...{key_hex}"
        
        status = f"{Fore.GREEN}Активен" if data['active'] else f"{Fore.RED}Завершен"
        
        print(
            f"{Fore.WHITE}Поток {tid:2}: {status}{Style.RESET_ALL} | "
            f"Обработано: {Fore.GREEN}{data['processed']:7,}{Style.RESET_ALL} | "
            f"Пропущено: {Fore.YELLOW}{data['skipped']:7,}{Style.RESET_ALL} | "
            f"Скорость: {Fore.CYAN}{data.get('speed', 0):7,.0f}/s{Style.RESET_ALL} | "
            f"Текущий: {Fore.MAGENTA}{last_key_display}{Style.RESET_ALL}"
        )
    
    print(f"\n{Fore.YELLOW}Для выхода нажмите Ctrl+C{Style.RESET_ALL}")

# ==================== ОСНОВНОЙ АЛГОРИТМ ====================

def process_range(thread_id, range_start, range_end, result_queue):
    """Обработка диапазона ключей с интеллектуальным пропуском"""
    try:
        current = range_start
        processed = 0
        skipped = 0
        last_speed_update = time.time()
        processed_since_update = 0
        
        while current <= range_end:
            key_hex = f"{current:064x}"
            
            if should_skip_key(key_hex):
                jump_to = calculate_jump(key_hex)
                if jump_to > current + 1000:  # Прыгаем только для больших блоков
                    skipped += (jump_to - current)
                    current = jump_to
                    continue
                else:
                    skipped += 1
                    current += 1
                    continue
            
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
            
            if processed % PROGRESS_UPDATE_ITERATIONS == 0:
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

def main():
    """Главная функция выполнения"""
    if not run_tests():
        return
    
    if not benchmark():
        return
    
    manager = Manager()
    result_queue = manager.Queue()
    progress_data = manager.dict()
    
    # Инициализация данных прогресса
    total = END_RANGE - START_RANGE
    chunk = total // NUM_THREADS
    for tid in range(NUM_THREADS):
        start = START_RANGE + tid * chunk
        end = start + chunk - 1 if tid < NUM_THREADS - 1 else END_RANGE
        progress_data[tid] = manager.dict({
            'start': start,
            'end': end,
            'current': start,
            'processed': 0,
            'skipped': 0,
            'speed': 0,
            'active': True
        })
    
    print(f"\n{Fore.YELLOW}🔹 Начало поиска с интеллектуальным пропуском...{Style.RESET_ALL}")
    time.sleep(2)
    
    try:
        with ProcessPoolExecutor(max_workers=NUM_THREADS) as executor:
            futures = [executor.submit(process_range, tid, 
                                     progress_data[tid]['start'],
                                     progress_data[tid]['end'],
                                     result_queue) 
                      for tid in range(NUM_THREADS)]
            
            active_threads = NUM_THREADS
            last_print_time = 0
            
            while active_threads > 0:
                while not result_queue.empty():
                    msg_type, data = result_queue.get_nowait()
                    
                    if msg_type == 'found':
                        print(f"\n{Fore.GREEN}🎉 Ключ найден: 0x{data}{Style.RESET_ALL}")
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
                        print(f"{Fore.RED}Ошибка в потоке: {data}{Style.RESET_ALL}")
                
                if time.time() - last_print_time >= MIN_UPDATE_INTERVAL:
                    print_progress(progress_data)
                    last_print_time = time.time()
                
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
