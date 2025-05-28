# -*- coding: utf-8 -*-
import hashlib
import coincurve
from concurrent.futures import ProcessPoolExecutor
import time
import os
import json
from numba import jit
import traceback
from multiprocessing import Manager, freeze_support, Value, Lock
from colorama import init, Fore, Back, Style
import sys
import signal
import re

# Инициализация colorama
init()

# Конфигурация
CONFIG = {
    "target_hash": "f6f5431d25bbf7b12e8add9af5e3475c44a0a5b8",
    "start_range": 0x780000000000000000,
    "end_range": 0x800000000000000000,
    "num_threads": max(8, os.cpu_count() + 4),
    "update_interval": 2.0,
    "state_file": "search_state.json",
    "backup_interval": 300  # 5 минут в секундах
}

class JumpCounter:
    def __init__(self, manager):
        self.total_jumps = manager.Value('i', 0)
        self.jump_stats = manager.dict({
            'pattern_small': manager.Value('i', 0),
            'pattern_medium': manager.Value('i', 0),
            'repeat_small': manager.Value('i', 0),
            'repeat_medium': manager.Value('i', 0),
            'repeat_large': manager.Value('i', 0),
            'repeat_huge': manager.Value('i', 0)
        })
        self.lock = manager.Lock()
    
    def increment(self, jump_type):
        with self.lock:
            self.total_jumps.value += 1
            if jump_type in self.jump_stats:
                self.jump_stats[jump_type].value += 1

@jit(nopython=True)
def detect_repeats_numba(key_part):
    """Поиск максимального количества последовательных повторений"""
    max_repeats = 1
    current = 1
    
    for i in range(1, len(key_part)):
        if key_part[i] == key_part[i-1]:
            current += 1
            if current > max_repeats:
                max_repeats = current
        else:
            current = 1
    
    return max_repeats

def detect_patterns(key_part):
    """Обнаружение паттернов без последовательных повторений"""
    # Проверка на однородность (все цифры или все буквы)
    if all(c.isdigit() for c in key_part):
        return 'all_digits'
    elif all(c.isalpha() for c in key_part):
        return 'all_letters'
    
    # Проверка на повторяющиеся паттерны (например, ababab)
    for pattern_length in [2, 3, 4]:
        pattern = key_part[:pattern_length]
        repeats = len(key_part) // pattern_length
        if pattern * repeats == key_part[:repeats*pattern_length]:
            return f'pattern_{pattern_length}'
    
    return None

def calculate_jump(key_hex, thread_id, jump_counter):
    """Определение размера прыжка по улучшенной системе"""
    original = int(key_hex, 16)
    last_17 = key_hex[-17:]
    
    # 1. Проверка паттернов без последовательных повторений
    pattern_type = detect_patterns(last_17)
    if pattern_type:
        if pattern_type.startswith('pattern_'):
            pattern_len = int(pattern_type.split('_')[1])
            if pattern_len <= 2:
                jump_size = 0x10000  # 65K
                jump_type = 'pattern_medium'
            else:
                jump_size = 0x1000  # 4K
                jump_type = 'pattern_small'
        elif pattern_type in ('all_digits', 'all_letters'):
            jump_size = 0x100000  # 1M
            jump_type = 'pattern_medium'
        
        jump_counter.increment(jump_type)
        new_pos = original + jump_size
        print(f"{Fore.CYAN}[Поток {thread_id}] Паттерн-прыжок {jump_size:,} ({pattern_type}): "
              f"0x{key_hex[-18:]} → 0x{f'{new_pos:x}'[-18:]}{Style.RESET_ALL}")
        return min(new_pos, CONFIG['end_range'])
    
    # 2. Проверка последовательных повторений (приоритетная)
    max_repeat = detect_repeats_numba(last_17)
    
    if max_repeat >= 14:
        jump_size = 0x100000000  # 4.2B (huge)
        jump_type = 'repeat_huge'
    elif max_repeat >= 10:
        jump_size = 0x10000000   # 256M (large)
        jump_type = 'repeat_large'
    elif max_repeat >= 7:
        jump_size = 0x100000     # 1M (medium)
        jump_type = 'repeat_medium'
    elif max_repeat >= 4:
        jump_size = 0x1000       # 4K (small)
        jump_type = 'repeat_small'
    else:
        return original + 1      # Обычный инкремент
    
    jump_counter.increment(jump_type)
    new_pos = original + jump_size
    
    if jump_size >= 0x10000:
        print(f"{Fore.MAGENTA}[Поток {thread_id}] Повтор-прыжок {jump_size:,} ({max_repeat} повторов): "
              f"0x{key_hex[-18:]} → 0x{f'{new_pos:x}'[-18:]}{Style.RESET_ALL}")
    
    return min(new_pos, CONFIG['end_range'])

def process_chunk(thread_id, start, end, result_queue, jump_counter):
    """Обработка диапазона ключей с улучшенной синхронизацией"""
    current = start
    chunk_size = end - start
    chunk_start_time = time.time()
    last_update = chunk_start_time
    processed = 0
    local_jumps = 0
    
    print(f"{Fore.BLUE}[Поток {thread_id}] Старт: 0x{start:064x} -> 0x{end:064x}{Style.RESET_ALL}")
    
    while current <= end:
        key_hex = f"{current:064x}"
        
        # Обязательное обновление статуса для каждого ключа
        try:
            # Сначала пытаемся сделать прыжок
            prev_current = current
            current = calculate_jump(key_hex, thread_id, jump_counter)
            if current > prev_current + 1:
                local_jumps += 1
                # Принудительное обновление после прыжка
                result_queue.put(('progress', {
                    'thread_id': thread_id,
                    'current': current,
                    'last_key': key_hex,
                    'processed': processed,
                    'speed': processed / (time.time() - chunk_start_time + 1e-9),
                    'percent': (current - start) / chunk_size * 100,
                    'elapsed': time.time() - chunk_start_time,
                    'local_jumps': local_jumps
                }))
                continue
            
            # Проверяем ключ только если не было прыжка
            key_bytes = bytes.fromhex(key_hex)
            pub_key = coincurve.PublicKey.from_secret(key_bytes).format(compressed=True)
            h = hashlib.new('ripemd160', hashlib.sha256(pub_key).digest()).hexdigest()
            
            if h == CONFIG['target_hash']:
                result_queue.put(('found', (thread_id, key_hex)))
                return
            
            processed += 1
            
            # Регулярное обновление статистики
            now = time.time()
            if now - last_update >= CONFIG['update_interval']:
                result_queue.put(('progress', {
                    'thread_id': thread_id,
                    'current': current,
                    'last_key': key_hex,
                    'processed': processed,
                    'speed': processed / (now - chunk_start_time),
                    'percent': (current - start) / chunk_size * 100,
                    'elapsed': now - chunk_start_time,
                    'local_jumps': local_jumps
                }))
                last_update = now
        
        except Exception as e:
            print(f"{Fore.RED}[Поток {thread_id}] Ошибка: {e}{Style.RESET_ALL}")
        
        current += 1
    
    result_queue.put(('done', thread_id))

# ... (остальные функции: run_benchmark, load_state, save_state, 
# calculate_percentage, print_status, setup_signal_handlers остаются без изменений)

def main():
    """Главная функция выполнения с улучшенной инициализацией"""
    benchmark = run_benchmark()
    state = load_state()
    
    manager = Manager()
    result_queue = manager.Queue()
    last_keys = manager.dict()
    total_processed = manager.Value('i', state['processed'] if state else 0)
    total_speed = manager.Value('f', 0.0)
    jump_counter = JumpCounter(manager)
    
    # Инициализация диапазонов с проверкой
    chunk_size = (CONFIG['end_range'] - CONFIG['start_range']) // CONFIG['num_threads']
    positions = []
    for tid in range(CONFIG['num_threads']):
        if state and 'positions' in state and tid < len(state['positions']):
            try:
                pos = int(state['positions'][tid], 16)
                positions.append(pos)
            except:
                positions.append(CONFIG['start_range'] + tid * chunk_size)
        else:
            positions.append(CONFIG['start_range'] + tid * chunk_size)
        last_keys[tid] = f"{positions[tid]:064x}"
        print(f"{Fore.GREEN}[Инициализация] Поток {tid} начинается с 0x{positions[tid]:064x}{Style.RESET_ALL}")
    
    # Проверка границ диапазонов
    for tid in range(CONFIG['num_threads']):
        start = positions[tid]
        end = CONFIG['start_range'] + (tid + 1) * chunk_size - 1 if tid < CONFIG['num_threads'] - 1 else CONFIG['end_range']
        if start >= end:
            print(f"{Fore.RED}Ошибка: неверный диапазон для потока {tid} (0x{start:064x} >= 0x{end:064x}){Style.RESET_ALL}")
            end = start + chunk_size
    
    stats = {
        'processed': total_processed.value,
        'speed': 0,
        'percent': calculate_percentage(positions),
        'elapsed': 0
    }
    
    setup_signal_handlers(positions, total_processed, jump_counter)
    
    try:
        with ProcessPoolExecutor(max_workers=CONFIG['num_threads']) as executor:
            futures = []
            for tid in range(CONFIG['num_threads']):
                start = positions[tid]
                end = CONFIG['start_range'] + (tid + 1) * chunk_size - 1 if tid < CONFIG['num_threads'] - 1 else CONFIG['end_range']
                futures.append(executor.submit(process_chunk, tid, start, end, result_queue, jump_counter))
            
            active_threads = CONFIG['num_threads']
            last_save_time = time.time()
            last_update_time = time.time()
            
            while active_threads > 0:
                if not result_queue.empty():
                    msg_type, data = result_queue.get()
                    
                    if msg_type == 'found':
                        tid, key = data
                        print(f"\n{Fore.GREEN}🎉 Ключ найден в потоке {tid}: 0x{key}{Style.RESET_ALL}")
                        for future in futures:
                            future.cancel()
                        if os.path.exists(CONFIG['state_file']):
                            os.remove(CONFIG['state_file'])
                        return
                    
                    elif msg_type == 'progress':
                        tid = data['thread_id']
                        last_keys[tid] = data['last_key']
                        total_processed.value += data['processed']
                        positions[tid] = data['current']
                        
                        if data['elapsed'] > 0:
                            current_speed = total_processed.value / data['elapsed']
                            total_speed.value = current_speed
                        
                        stats.update({
                            'processed': total_processed.value,
                            'speed': total_speed.value,
                            'percent': calculate_percentage(positions),
                            'elapsed': data['elapsed']
                        })
                    
                    elif msg_type == 'done':
                        active_threads -= 1
                
                current_time = time.time()
                if current_time - last_update_time >= CONFIG['update_interval']:
                    print_status(stats, dict(last_keys), jump_counter)
                    last_update_time = current_time
                
                if current_time - last_save_time > CONFIG['backup_interval']:
                    if save_state(positions, total_processed, jump_counter):
                        last_save_time = current_time
                        print(f"\n{Fore.GREEN}Автосохранение выполнено.{Style.RESET_ALL}")
                
                time.sleep(0.1)
            
            print(f"\n{Fore.YELLOW}Поиск завершен. Ключ не найден.{Style.RESET_ALL}")
            if os.path.exists(CONFIG['state_file']):
                os.remove(CONFIG['state_file'])
    
    except Exception as e:
        print(f"\n{Fore.RED}Ошибка: {str(e)}{Style.RESET_ALL}")
        traceback.print_exc()
        save_state(positions, total_processed, jump_counter)

if __name__ == "__main__":
    freeze_support()
    main()
