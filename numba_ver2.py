# -*- coding: utf-8 -*-
import hashlib
import coincurve
from concurrent.futures import ProcessPoolExecutor
import time
import os
import random
from numba import jit
import traceback
from multiprocessing import Manager, freeze_support
from colorama import init, Fore, Back, Style

# Инициализация colorama
init()

# Конфигурация
TEST_KEY = "0000000000000000000000000000000000000000000000000000000000000001"
TEST_HASH = "751e76e8199196d454941c45d1b3a323f1433bd6"
TARGET_HASH = "5db8cda53a6a002db10365967d7f85d19e171b10"
START_RANGE = 0x349b84b6431a5c4ef1
END_RANGE = 0x349b84b6431a6c4ef9
NUM_THREADS = max(8, os.cpu_count() + 4)  # Автоподбор потоков
MIN_UPDATE_INTERVAL = 1.0

# ==================== УЛУЧШЕННЫЕ ФУНКЦИИ ПРОВЕРКИ ====================

@jit(nopython=True)
def detect_repeats(key_hex):
    """Агрессивное обнаружение повторений с Numba"""
    max_repeats = 1
    current_repeats = 1
    prev_char = key_hex[0]
    
    for c in key_hex[1:]:
        if c == prev_char:
            current_repeats += 1
            if current_repeats > max_repeats:
                max_repeats = current_repeats
                if max_repeats >= 17:  # Максимально возможный повтор
                    return max_repeats
        else:
            current_repeats = 1
        prev_char = c
    
    return max_repeats

def should_skip_key(key_hex):
    """Оптимизированная проверка для быстрых прыжков"""
    # Тестовый ключ всегда проверяется
    if key_hex == "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a":
        return False
    
    # Быстрая проверка через Numba
    repeat_count = detect_repeats(key_hex[-17:])  # Анализируем только последние 17 символов
    if repeat_count >= 4:  # Пропускаем при 4+ повторениях
        return True
    
    return False

def calculate_jump(key_hex, thread_id):
    """Максимально агрессивные прыжки с безопасными границами"""
    original = int(key_hex, 16)
    last_17 = key_hex[-17:]
    
    # Определяем максимальную последовательность повторений
    max_repeat = 1
    current_repeat = 1
    prev_char = last_17[0]
    
    for c in last_17[1:]:
        if c == prev_char:
            current_repeat += 1
            if current_repeat > max_repeat:
                max_repeat = current_repeat
        else:
            current_repeat = 1
        prev_char = c
    
    # Размер прыжка зависит от количества повторений
    if max_repeat >= 12:
        jump_size = 0x100000000  # 1,048,576 ключей для очень длинных повторов
    elif max_repeat >= 8:
        jump_size = 0x1000000   # 65,536 ключей
    elif max_repeat >= 6:
        jump_size = 0x10000    # 4,096 ключей
    elif max_repeat >= 4:
        jump_size = 0x100     # 256 ключей
    else:
        return original + 1   # Без прыжка
    
    new_pos = original + jump_size
    
    # Логирование только больших прыжков
    if jump_size >= 0x1000:
        print(f"{Fore.MAGENTA}[Поток {thread_id}] Прыжок на {jump_size:,} "
              f"при {max_repeat} повторениях: "
              f"0x...{key_hex[-8:]} → 0x...{f'{new_pos:x}'[-8:]}{Style.RESET_ALL}")
    
    return min(new_pos, END_RANGE)

# ==================== ОПТИМИЗИРОВАННАЯ ОБРАБОТКА ====================

def process_range(thread_id, range_start, range_end, result_queue):
    """Максимально быстрая обработка с прыжками"""
    try:
        current = range_start
        processed = 0
        skipped = 0
        last_update = time.time()
        
        while current <= range_end:
            key_hex = f"{current:064x}"
            
            if should_skip_key(key_hex):
                jump_to = calculate_jump(key_hex, thread_id)
                skipped += jump_to - current
                current = jump_to
                continue
            
            # Проверка ключа
            try:
                pub_key = coincurve.PublicKey.from_secret(bytes.fromhex(key_hex)).format(compressed=True)
                h = hashlib.new('ripemd160', hashlib.sha256(pub_key).digest()).hexdigest()
                
                if h == TARGET_HASH:
                    result_queue.put(('found', key_hex))
                    return
                
                processed += 1
                
                # Отчет о прогрессе
                if time.time() - last_update > 1.0:
                    result_queue.put(('progress', {
                        'thread_id': thread_id,
                        'current': current,
                        'processed': processed,
                        'skipped': skipped,
                        'speed': processed / max(1, time.time() - last_update)
                    }))
                    last_update = time.time()
                    
            except Exception as e:
                skipped += 1
            
            current += 1
        
        result_queue.put(('done', thread_id))
    except Exception as e:
        result_queue.put(('error', {'thread_id': thread_id, 'error': str(e), 'traceback': traceback.format_exc()}))

# ==================== ИНТЕРФЕЙС И ВЫВОД ====================

def print_progress(progress_data, jump_history):
    """Улучшенный вывод прогресса"""
    os.system('cls' if os.name == 'nt' else 'clear')
    
    # Вывод заголовка
    print(f"{Fore.CYAN}=== ПРОГРЕСС ПОИСКА ==={Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Диапазон: 0x{START_RANGE:016x} - 0x{END_RANGE:016x}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Активные потоки: {sum(1 for p in progress_data.values() if p['active'])}/{NUM_THREADS}{Style.RESET_ALL}")
    
    # Вывод последних прыжков
    print(f"\n{Fore.MAGENTA}=== ПОСЛЕДНИЕ ПРЫЖКИ ==={Style.RESET_ALL}")
    for jump in jump_history[-3:]:
        print(f"Поток {jump['thread_id']}: +{jump['to']-jump['from']:,} ключей (пропущено {jump['skipped']:,})")
    
    # Статистика потоков
    print(f"\n{Fore.BLUE}=== СТАТИСТИКА ПОТОКОВ ==={Style.RESET_ALL}")
    for tid in sorted(progress_data.keys()):
        data = progress_data[tid]
        status = f"{Fore.GREEN}Активен" if data['active'] else f"{Fore.RED}Завершен"
        print(f"Поток {tid:2}: {status}{Style.RESET_ALL} | "
              f"Обработано: {Fore.GREEN}{data['processed']:9,}{Style.RESET_ALL} | "
              f"Пропущено: {Fore.YELLOW}{data['skipped']:9,}{Style.RESET_ALL} | "
              f"Скорость: {Fore.CYAN}{data.get('speed', 0):7,.0f}/s{Style.RESET_ALL}")
    
    print(f"\n{Fore.YELLOW}Для выхода нажмите Ctrl+C{Style.RESET_ALL}")

# ==================== ОСНОВНАЯ ПРОГРАММА ====================

def main():
    """Главная функция выполнения"""
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
    print(f"{Fore.YELLOW}Диапазон: 0x{START_RANGE:016x} - 0x{END_RANGE:016x}{Style.RESET_ALL}")
    time.sleep(2)
    
    try:
        with ProcessPoolExecutor(max_workers=NUM_THREADS) as executor:
            futures = [executor.submit(process_range, tid, 
                                      progress_data[tid]['start'],
                                      progress_data[tid]['end'],
                                      result_queue) 
                      for tid in range(NUM_THREADS)]
            
            active_threads = NUM_THREADS
            last_print_time = time.time()
            
            while active_threads > 0:
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
                        print(data['traceback'])
                
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
