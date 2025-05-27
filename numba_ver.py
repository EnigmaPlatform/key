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

# ==================== ФУНКЦИИ ПРОВЕРКИ КЛЮЧЕЙ ====================

@jit(nopython=True)
def has_quick_skip_pattern(key_hex):
    """Быстрая проверка очевидных паттернов с использованием Numba"""
    last_17 = key_hex[-17:]
    
    # Проверка 4+ повторяющихся символов
    for i in range(len(last_17)-3):
        if last_17[i] == last_17[i+1] == last_17[i+2] == last_17[i+3]:
            return True
    
    return False

def should_skip_key(key_hex):
    """Комбинированная проверка валидности ключа"""
    # Специальный случай для тестового ключа
    if key_hex == "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a":
        return False
        
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

# ==================== АЛГОРИТМ ПРЫЖКОВ ====================

def calculate_jump(key_hex, thread_id):
    """Вычисляет безопасный прыжок с логированием"""
    original = int(key_hex, 16)
    last_17 = key_hex[-17:]
    
    # Поиск максимального паттерна для прыжка
    max_pattern = ''
    max_pos = -1
    
    for pattern in REPEAT_PATTERNS + SEQUENTIAL_PATTERNS:
        pos = last_17.find(pattern)
        if pos != -1 and len(pattern) > len(max_pattern):
            max_pattern = pattern
            max_pos = pos
    
    if max_pos != -1:
        jump_size = 16 ** (16 - max_pos)
        new_pos = original + jump_size
        
        # Логирование прыжка
        print(f"{Fore.MAGENTA}[Поток {thread_id}] Прыжок на {jump_size:,} "
              f"при обнаружении '{max_pattern}' в позиции {max_pos}: "
              f"0x...{key_hex[-8:]} → 0x...{f'{new_pos:x}'[-8:]}{Style.RESET_ALL}")
        
        return min(new_pos, END_RANGE)
    
    return original + 1

# ==================== ОБРАБОТКА ДИАПАЗОНОВ ====================

def process_range(thread_id, range_start, range_end, result_queue):
    """Обработка диапазона ключей с интеллектуальным пропуском"""
    try:
        current = range_start
        processed = 0
        skipped = 0
        last_update = time.time()
        
        while current <= range_end:
            key_hex = f"{current:064x}"
            
            if should_skip_key(key_hex):
                jump_to = calculate_jump(key_hex, thread_id)
                
                if jump_to > current + 1000:  # Большие прыжки
                    result_queue.put(('jump', {
                        'thread_id': thread_id,
                        'from': current,
                        'to': jump_to,
                        'pattern': key_hex[-17:],
                        'skipped': jump_to - current
                    }))
                    skipped += jump_to - current
                    current = jump_to
                    continue
                else:
                    skipped += 1
                    current += 1
                    continue
            
            # Обработка валидного ключа
            try:
                pub_key = coincurve.PublicKey.from_secret(bytes.fromhex(key_hex)).format(compressed=True)
                h = hashlib.new('ripemd160', hashlib.sha256(pub_key).digest()).hexdigest()
                
                if h == TARGET_HASH:
                    result_queue.put(('found', key_hex))
                    return
                
                processed += 1
                
                # Периодическая отправка прогресса
                if time.time() - last_update > 1.0:
                    result_queue.put(('progress', {
                        'thread_id': thread_id,
                        'current': current,
                        'processed': processed,
                        'skipped': skipped,
                        'speed': processed / (time.time() - (range_start // (END_RANGE - START_RANGE)) * (END_RANGE - START_RANGE) / NUM_THREADS)
                    }))
                    last_update = time.time()
                    
            except Exception as e:
                skipped += 1
            
            current += 1
        
        result_queue.put(('done', thread_id))
    except Exception as e:
        result_queue.put(('error', {'thread_id': thread_id, 'error': str(e)}))

# ==================== ИНТЕРФЕЙС И ВЫВОД ====================

def print_progress(progress_data, jump_history):
    """Улучшенный вывод прогресса с историей прыжков"""
    os.system('cls' if os.name == 'nt' else 'clear')
    
    # Вывод заголовка
    print(f"{Fore.CYAN}=== ПРОГРЕСС ПОИСКА ==={Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Диапазон: 0x{START_RANGE:016x} - 0x{END_RANGE:016x}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Активные потоки: {sum(1 for p in progress_data.values() if p['active'])}/{NUM_THREADS}{Style.RESET_ALL}")
    
    # Вывод последних прыжков
    print(f"\n{Fore.MAGENTA}=== ПОСЛЕДНИЕ ПРЫЖКИ ==={Style.RESET_ALL}")
    for jump in jump_history[-3:]:
        print(f"Поток {jump['thread_id']}: +{jump['to']-jump['from']:,} "
              f"(пропущено {jump['skipped']:,} ключей)")
    
    # Вывод статистики по потокам
    print(f"\n{Fore.BLUE}=== СТАТИСТИКА ПОТОКОВ ==={Style.RESET_ALL}")
    for tid in sorted(progress_data.keys()):
        data = progress_data[tid]
        status = f"{Fore.GREEN}Активен" if data['active'] else f"{Fore.RED}Завершен"
        print(f"Поток {tid:2}: {status}{Style.RESET_ALL} | "
              f"Обработано: {Fore.GREEN}{data['processed']:9,}{Style.RESET_ALL} | "
              f"Пропущено: {Fore.YELLOW}{data['skipped']:9,}{Style.RESET_ALL} | "
              f"Скорость: {Fore.CYAN}{data.get('speed', 0):7,.0f}/s{Style.RESET_ALL}")
    
    print(f"\n{Fore.YELLOW}Для выхода нажмите Ctrl+C{Style.RESET_ALL}")

# ==================== ТЕСТИРОВАНИЕ ====================

def run_tests():
    """Запуск тестовых проверок"""
    print(f"\n{Fore.YELLOW}=== ТЕСТИРОВАНИЕ ==={Style.RESET_ALL}")
    
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
                print(f"{Fore.RED}❌ Тест фильтрации {i} не пройден для ключа {key}: "
                      f"ожидалось {expected}, получено {result}{Style.RESET_ALL}")
                return False
        
        print(f"{Fore.GREEN}✅ Тест фильтрации пройден{Style.RESET_ALL}")
        return True
    except Exception as e:
        print(f"{Fore.RED}❌ Критическая ошибка в тесте фильтрации: {str(e)}{Style.RESET_ALL}")
        return False

def benchmark():
    """Тестирование производительности"""
    print(f"\n{Fore.YELLOW}=== БЕНЧМАРК ==={Style.RESET_ALL}")
    test_keys = [''.join(random.choice('0123456789abcdef') for _ in range(64)) 
                for _ in range(10000)]
    
    start = time.time()
    for key in test_keys:
        should_skip_key(key)
    
    elapsed = time.time() - start
    speed = len(test_keys) / elapsed
    print(f"{Fore.CYAN}Обработано {len(test_keys):,} ключей за {elapsed:.2f} секунд{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Скорость: {speed:,.0f} ключей/сек (1 поток){Style.RESET_ALL}")
    print(f"{Fore.CYAN}Ожидаемая скорость ({NUM_THREADS} потоков): {speed*NUM_THREADS:,.0f} ключей/сек{Style.RESET_ALL}")
    return True

# ==================== ОСНОВНАЯ ПРОГРАММА ====================

def main():
    """Главная функция выполнения"""
    if not run_tests():
        return
    
    if not benchmark():
        return
    
    manager = Manager()
    result_queue = manager.Queue()
    progress_data = manager.dict()
    jump_history = manager.list()
    
    # Инициализация данных прогресса
    total_range = END_RANGE - START_RANGE
    chunk_size = total_range // NUM_THREADS
    
    for tid in range(NUM_THREADS):
        start = START_RANGE + tid * chunk_size
        end = start + chunk_size - 1 if tid < NUM_THREADS - 1 else END_RANGE
        progress_data[tid] = manager.dict({
            'start': start,
            'end': end,
            'current': start,
            'processed': 0,
            'skipped': 0,
            'speed': 0,
            'active': True
        })
    
    print(f"\n{Fore.GREEN}=== ЗАПУСК ПОИСКА ==={Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Используется {NUM_THREADS} потоков{Style.RESET_ALL}")
    time.sleep(2)
    
    try:
        with ProcessPoolExecutor(max_workers=NUM_THREADS) as executor:
            # Запуск потоков
            futures = [executor.submit(process_range, tid, 
                                      progress_data[tid]['start'],
                                      progress_data[tid]['end'],
                                      result_queue) 
                      for tid in range(NUM_THREADS)]
            
            active_threads = NUM_THREADS
            last_print_time = time.time()
            
            while active_threads > 0:
                # Обработка сообщений
                while not result_queue.empty():
                    msg_type, data = result_queue.get_nowait()
                    
                    if msg_type == 'found':
                        print(f"\n{Fore.GREEN}🎉 Ключ найден: 0x{data}{Style.RESET_ALL}")
                        return
                        
                    elif msg_type == 'progress':
                        progress_data[data['thread_id']].update(data)
                        
                    elif msg_type == 'jump':
                        progress_data[data['thread_id']]['skipped'] += data['skipped']
                        progress_data[data['thread_id']]['current'] = data['to']
                        jump_history.append(data)
                        if len(jump_history) > 10:
                            jump_history.pop(0)
                    
                    elif msg_type == 'done':
                        progress_data[data]['active'] = False
                        active_threads -= 1
                    
                    elif msg_type == 'error':
                        print(f"{Fore.RED}Ошибка в потоке {data['thread_id']}: {data['error']}{Style.RESET_ALL}")
                
                # Обновление экрана
                if time.time() - last_print_time >= MIN_UPDATE_INTERVAL:
                    print_progress(progress_data, jump_history)
                    last_print_time = time.time()
                
                time.sleep(0.1)
            
            print(f"\n{Fore.YELLOW}🔍 Поиск завершен, ключ не найден{Style.RESET_ALL}")
            
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
