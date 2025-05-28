# -*- coding: utf-8 -*-
import hashlib
import coincurve
from concurrent.futures import ProcessPoolExecutor
import time
import os
import json
from numba import jit
import traceback
from multiprocessing import Manager, freeze_support
from colorama import init, Fore, Back, Style
import sys

# Инициализация colorama
init()

# Конфигурация
CONFIG = {
    "target_hash": "5db8cda53a6a002db10365967d7f85d19e171b10",
    "start_range": 0x349b84b60000000000,
    "end_range": 0x349b84b6431a6c4ef9,
    "num_threads": max(8, os.cpu_count() + 6),
    "update_interval": 2.0,
    "state_file": "search_state.json"
}

def run_benchmark():
    """Запуск бенчмарка системы для оценки производительности"""
    print(f"\n{Fore.CYAN}=== ЗАПУСК БЕНЧМАРКА ==={Style.RESET_ALL}")
    
    # Тест полного цикла
    test_key = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
    start = time.time()
    count = 0
    while time.time() - start < 2.0:
        key_bytes = bytes.fromhex(test_key)
        pub_key = coincurve.PublicKey.from_secret(key_bytes).format(compressed=True)
        hashlib.new('ripemd160', hashlib.sha256(pub_key).digest())
        count += 1
    full_cycle_speed = count / 2.0
    
    print(f"{Fore.GREEN}Результаты бенчмарка:{Style.RESET_ALL}")
    print(f"Полный цикл проверки ключа: {full_cycle_speed:,.0f} операций/сек")
    
    return {
        'full_cycle_speed': full_cycle_speed,
        'timestamp': time.time()
    }

def load_state():
    """Загрузка состояния из файла с подтверждением пользователя"""
    if not os.path.exists(CONFIG['state_file']):
        return None
        
    print(f"\n{Fore.YELLOW}Обнаружен файл сохранения: {CONFIG['state_file']}{Style.RESET_ALL}")
    while True:
        choice = input("Хотите продолжить с предыдущего места? (y/n): ").strip().lower()
        if choice in ('y', 'n'):
            break
        print(f"{Fore.RED}Пожалуйста, введите 'y' или 'n'{Style.RESET_ALL}")
    
    if choice == 'y':
        try:
            with open(CONFIG['state_file'], 'r') as f:
                state = json.load(f)
                
            if not isinstance(state, dict) or 'positions' not in state or 'processed' not in state:
                raise ValueError("Неверный формат файла состояния")
                
            if 'config' in state and (state['config']['target_hash'] != CONFIG['target_hash'] or 
                                    state['config']['end_range'] != CONFIG['end_range']):
                raise ValueError("Конфигурация в файле состояния не совпадает с текущей")
                
            if isinstance(state['positions'], dict):
                state['positions'] = [state['positions'][str(k)] for k in range(len(state['positions']))]
                
            print(f"{Fore.GREEN}Загружено сохраненное состояние{Style.RESET_ALL}")
            return state
        except Exception as e:
            print(f"{Fore.RED}Ошибка загрузки состояния: {e}{Style.RESET_ALL}")
            traceback.print_exc()
            return None
    return None

def save_state(current_positions, processed_keys):
    """Сохранение текущего состояния в файл"""
    positions_list = [current_positions[i] for i in range(len(current_positions))]
    
    state = {
        'positions': positions_list,
        'processed': processed_keys,
        'timestamp': time.time(),
        'config': CONFIG
    }
    
    try:
        with open(CONFIG['state_file'], 'w') as f:
            json.dump(state, f, indent=2)
        return True
    except Exception as e:
        print(f"{Fore.RED}Ошибка сохранения состояния: {e}{Style.RESET_ALL}")
        return False

@jit(nopython=True)
def detect_repeats(key_hex):
    """Оптимизированная проверка повторений"""
    max_repeats = 1
    current = 1
    for i in range(1, len(key_hex)):
        if key_hex[i] == key_hex[i-1]:
            current += 1
            if current > max_repeats:
                max_repeats = current
                if max_repeats >= 12:
                    return max_repeats
        else:
            current = 1
    return max_repeats

def process_chunk(thread_id, start, end, result_queue):
    """Обработка диапазона ключей"""
    current = start
    chunk_size = end - start
    chunk_start_time = time.time()
    last_update = chunk_start_time
    processed = 0
    last_position = start
    
    while current <= end:
        key_hex = f"{current:064x}"
        
        if detect_repeats(key_hex[-16:]) < 4:
            try:
                key_bytes = bytes.fromhex(key_hex)
                pub_key = coincurve.PublicKey.from_secret(key_bytes).format(compressed=True)
                h = hashlib.new('ripemd160', hashlib.sha256(pub_key).digest()).hexdigest()
                
                if h == CONFIG['target_hash']:
                    result_queue.put(('found', key_hex))
                    return
                
                processed += 1
                last_position = current
                
                now = time.time()
                if now - last_update >= CONFIG['update_interval']:
                    elapsed = now - chunk_start_time
                    speed = processed / elapsed if elapsed > 0 else 0
                    percent = (current - start) / chunk_size * 100
                    
                    result_queue.put(('progress', {
                        'thread_id': thread_id,
                        'current': current,
                        'last_position': last_position,
                        'processed': processed,
                        'speed': speed,
                        'percent': percent,
                        'elapsed': elapsed
                    }))
                    last_update = now
                    
            except Exception:
                pass
        
        current += 1
    
    result_queue.put(('done', thread_id))

def print_status(stats, current_positions):
    """Оптимизированный вывод статуса"""
    os.system('cls' if os.name == 'nt' else 'clear')
    
    # Общая информация
    print(f"{Fore.CYAN}=== ИНФОРМАЦИЯ О ПОИСКЕ ==={Style.RESET_ALL}")
    print(f"Потоков: {CONFIG['num_threads']} | Загрузка CPU: {min(100, CONFIG['num_threads'] * 100 / os.cpu_count()):.0f}%")
    print(f"Диапазон: 0x{CONFIG['start_range']:016x} - 0x{CONFIG['end_range']:016x}")
    
    # Производительность
    print(f"\n{Fore.BLUE}=== ПРОИЗВОДИТЕЛЬНОСТЬ ==={Style.RESET_ALL}")
    print(f"Скорость: {stats['speed']:,.0f} ключей/сек")
    
    # Прогресс
    print(f"\n{Fore.GREEN}=== ПРОГРЕСС ==={Style.RESET_ALL}")
    print(f"Обработано: {stats['processed']:,} ключей")
    print(f"Прогресс: {stats['percent']:.6f}%")
    print(f"Прошло времени: {stats['elapsed']/60:.1f} минут")
    
    # Позиции потоков
    print(f"\n{Fore.YELLOW}ТЕКУЩИЕ ПОЗИЦИИ ПОТОКОВ:{Style.RESET_ALL}")
    for tid in sorted(current_positions.keys()):
        pos = current_positions[tid]
        percent = (pos - CONFIG['start_range']) / (CONFIG['end_range'] - CONFIG['start_range']) * 100
        print(f"Поток {tid:2}: 0x{pos:016x} ({percent:.4f}%)")
    
    # Прогноз
    if stats['percent'] > 0:
        remaining = (100 - stats['percent']) * stats['elapsed'] / stats['percent']
        print(f"\n{Fore.MAGENTA}=== ПРОГНОЗ ==={Style.RESET_ALL}")
        print(f"Осталось времени: {remaining/3600:.1f} часов")
        print(f"Примерное завершение: {time.ctime(time.time() + remaining)}")
    
    print(f"\n{Fore.WHITE}Для выхода нажмите Ctrl+C (состояние будет сохранено){Style.RESET_ALL}")

def main():
    """Оптимизированная главная функция"""
    benchmark = run_benchmark()
    time.sleep(1)
    
    state = load_state()
    
    manager = Manager()
    result_queue = manager.Queue()
    current_positions = manager.dict()
    processed_keys = manager.Value('i', 0)
    total_processed = manager.Value('i', 0)
    
    chunk_size = (CONFIG['end_range'] - CONFIG['start_range']) // CONFIG['num_threads']
    chunks = []
    
    if state and isinstance(state.get('positions'), list):
        positions = state['positions']
        for tid in range(min(CONFIG['num_threads'], len(positions))):
            start = positions[tid]
            end = CONFIG['start_range'] + (tid + 1) * chunk_size - 1 if tid < CONFIG['num_threads'] - 1 else CONFIG['end_range']
            chunks.append((tid, start, end))
            current_positions[tid] = start
        
        for tid in range(len(positions), CONFIG['num_threads']):
            start = CONFIG['start_range'] + tid * chunk_size
            end = CONFIG['start_range'] + (tid + 1) * chunk_size - 1 if tid < CONFIG['num_threads'] - 1 else CONFIG['end_range']
            chunks.append((tid, start, end))
            current_positions[tid] = start
            
        processed_keys.value = state.get('processed', 0)
        total_processed.value = state.get('processed', 0)
    else:
        for tid in range(CONFIG['num_threads']):
            start = CONFIG['start_range'] + tid * chunk_size
            end = CONFIG['start_range'] + (tid + 1) * chunk_size - 1 if tid < CONFIG['num_threads'] - 1 else CONFIG['end_range']
            chunks.append((tid, start, end))
            current_positions[tid] = start
    
    stats = {
        'processed': total_processed.value,
        'speed': 0,
        'percent': 0,
        'elapsed': 0
    }
    
    try:
        with ProcessPoolExecutor(max_workers=CONFIG['num_threads']) as executor:
            futures = [executor.submit(process_chunk, tid, start, end, result_queue) 
                      for tid, start, end in chunks]
            
            active_threads = CONFIG['num_threads']
            last_print_time = time.time()
            last_save_time = time.time()
            
            while active_threads > 0:
                while not result_queue.empty():
                    msg_type, data = result_queue.get_nowait()
                    
                    if msg_type == 'found':
                        print(f"\n{Fore.GREEN}?? Ключ найден: 0x{data}{Style.RESET_ALL}")
                        for future in futures:
                            future.cancel()
                        if os.path.exists(CONFIG['state_file']):
                            os.remove(CONFIG['state_file'])
                        return
                        
                    elif msg_type == 'progress':
                        current_positions[data['thread_id']] = data['last_position']
                        delta_processed = data['processed']
                        total_processed.value += delta_processed
                        
                        stats['processed'] = total_processed.value
                        stats['speed'] = data['speed']
                        stats['percent'] = max(stats['percent'], data['percent'])
                        stats['elapsed'] = max(stats['elapsed'], data['elapsed'])
                    
                    elif msg_type == 'done':
                        active_threads -= 1
                
                if time.time() - last_print_time >= CONFIG['update_interval']:
                    print_status(stats, dict(current_positions))
                    last_print_time = time.time()
                
                if time.time() - last_save_time > 300:
                    if save_state(dict(current_positions), total_processed.value):
                        last_save_time = time.time()
                
                time.sleep(0.1)
            
            print(f"\n{Fore.YELLOW}Поиск завершен. Ключ не найден.{Style.RESET_ALL}")
            if os.path.exists(CONFIG['state_file']):
                os.remove(CONFIG['state_file'])
    
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Сохранение состояния перед выходом...{Style.RESET_ALL}")
        save_state(dict(current_positions), total_processed.value)
        print(f"{Fore.GREEN}Сохранено текущее состояние в {CONFIG['state_file']}{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}Ошибка: {str(e)}{Style.RESET_ALL}")
        traceback.print_exc()
        save_state(dict(current_positions), total_processed.value)

if __name__ == "__main__":
    freeze_support()
    main()
