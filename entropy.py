# -*- coding: utf-8 -*-
import hashlib
import coincurve
from concurrent.futures import ProcessPoolExecutor
import time
import os
import json
from multiprocessing import Manager, freeze_support, Value
from colorama import init, Fore, Style
import sys
import signal
import math

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
    "min_entropy": 2.5  # Минимальная энтропия для валидного ключа
}

def calculate_entropy(key_hex):
    """Вычисляет энтропию ключа"""
    freq = {}
    for c in key_hex:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    total = len(key_hex)
    for count in freq.values():
        p = float(count) / total
        entropy -= p * math.log(p, 2)
    return entropy

def is_valid_key(key_hex):
    """Проверяет ключ на валидность по энтропии"""
    entropy = calculate_entropy(key_hex)
    return entropy >= CONFIG['min_entropy']

def process_chunk(thread_id, start, end, result_queue, stats):
    current = start
    chunk_size = end - start
    chunk_start_time = time.time()
    last_update = chunk_start_time
    local_checked = 0
    local_processed = 0
    
    while current <= end:
        key_hex = f"{current:064x}"
        local_processed += 1
        
        if is_valid_key(key_hex):
            try:
                key_bytes = bytes.fromhex(key_hex)
                pub_key = coincurve.PublicKey.from_secret(key_bytes).format(compressed=True)
                h = hashlib.new('ripemd160', hashlib.sha256(pub_key).digest()).hexdigest()
                
                if h == CONFIG['target_hash']:
                    result_queue.put(('found', (thread_id, key_hex)))
                    return
                
                local_checked += 1
            except Exception as e:
                pass
        
        # Отправляем обновление статистики
        now = time.time()
        if now - last_update >= CONFIG['update_interval'] or current == end:
            result_queue.put(('progress', {
                'thread_id': thread_id,
                'current': current,
                'last_key': key_hex,
                'local_checked': local_checked,
                'local_processed': local_processed,
                'percent': (current - start) / chunk_size * 100,
                'elapsed': now - chunk_start_time
            }))
            local_checked = 0
            local_processed = 0
            last_update = now
        
        current += 1
    
    result_queue.put(('done', thread_id))

def print_status(total_stats, last_keys):
    os.system('cls' if os.name == 'nt' else 'clear')
    
    elapsed = time.time() - total_stats['start_time']
    checked = total_stats['actually_checked']
    processed = total_stats['total_processed']
    
    actual_speed = processed / elapsed if elapsed > 0 else 0
    check_speed = checked / elapsed if elapsed > 0 else 0
    
    print(f"{Fore.CYAN}=== ИНФОРМАЦИЯ О ПОИСКЕ ==={Style.RESET_ALL}")
    print(f"Потоков: {CONFIG['num_threads']} | Скорость: {actual_speed:,.0f} ключ/сек (всего)")
    print(f"Проверок: {check_speed:,.0f} ключ/сек | Энтропия > {CONFIG['min_entropy']}")
    print(f"Проверено: {checked:,} | Всего: {processed:,} | Прогресс: {total_stats['percent']:.8f}%")
    print(f"Прошло времени: {elapsed/60:.1f} минут")
    
    print(f"\n{Fore.YELLOW}ПОСЛЕДНИЕ КЛЮЧИ:{Style.RESET_ALL}")
    for tid in sorted(last_keys.keys()):
        print(f"Поток {tid:2}: 0x{last_keys[tid][-18:]}")
    
    if total_stats['percent'] > 0 and total_stats['percent'] < 100:
        remaining = (100 - total_stats['percent']) * elapsed / total_stats['percent']
        print(f"\n{Fore.MAGENTA}Осталось: ~{remaining/3600:.1f} часов | Завершение: {time.ctime(time.time() + remaining)}{Style.RESET_ALL}")

def load_state():
    if not os.path.exists(CONFIG['state_file']):
        return None
        
    try:
        with open(CONFIG['state_file'], 'r') as f:
            state = json.load(f)
        
        print(f"\n{Fore.YELLOW}Найден файл состояния: {CONFIG['state_file']}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}=== СОХРАНЕННОЕ СОСТОЯНИЕ ===")
        print(f"Прогресс: {state.get('percent', 0):.8f}%")
        print(f"Проверено: {state.get('actually_checked', 0):,} ключей")
        print(f"Всего обработано: {state.get('total_processed', 0):,} ключей")
        print(f"Позиции потоков:{Style.RESET_ALL}")
        for tid, pos in enumerate(state.get('positions', [])):
            print(f"  Поток {tid}: 0x{f'{int(pos, 16):x}'[-18:]}")
        
        while True:
            choice = input("\nПродолжить (y) или начать заново (n): ").lower()
            if choice == 'y':
                return state
            elif choice == 'n':
                os.remove(CONFIG['state_file'])
                print(f"{Fore.GREEN}Файл состояния удален.{Style.RESET_ALL}")
                return None
            else:
                print(f"{Fore.RED}Введите y или n{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Ошибка загрузки: {e}{Style.RESET_ALL}")
        return None

def save_state(positions, stats):
    temp_file = CONFIG['state_file'] + ".tmp"
    
    try:
        state_data = {
            'positions': [f"{pos:064x}" for pos in positions],
            'actually_checked': stats['actually_checked'],
            'total_processed': stats['total_processed'],
            'timestamp': time.time(),
            'percent': calculate_percentage(positions),
            'config': CONFIG
        }
        
        with open(temp_file, 'w') as f:
            json.dump(state_data, f, indent=2)
        
        if os.path.exists(CONFIG['state_file']):
            os.remove(CONFIG['state_file'])
        os.rename(temp_file, CONFIG['state_file'])
        
        return True
    except Exception as e:
        print(f"{Fore.RED}Ошибка сохранения: {e}{Style.RESET_ALL}")
        if os.path.exists(temp_file):
            os.remove(temp_file)
        return False

def calculate_percentage(positions):
    total_range = CONFIG['end_range'] - CONFIG['start_range']
    if total_range <= 0:
        return 0.0
    progress = sum(pos - CONFIG['start_range'] for pos in positions) / total_range
    return (progress / CONFIG['num_threads']) * 100

def setup_signal_handlers(positions, stats):
    def signal_handler(sig, frame):
        print(f"\n{Fore.YELLOW}Сохранение состояния...{Style.RESET_ALL}")
        save_state(positions, stats)
        print(f"{Fore.GREEN}Сохранено. Выход.{Style.RESET_ALL}")
        os._exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

def main():
    state = load_state()
    
    manager = Manager()
    result_queue = manager.Queue()
    last_keys = manager.dict()
    
    # Инициализация статистики
    total_stats = {
        'start_time': time.time(),
        'actually_checked': state['actually_checked'] if state else 0,
        'total_processed': state['total_processed'] if state else 0,
        'percent': 0.0
    }
    
    # Инициализация диапазонов
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
    
    setup_signal_handlers(positions, total_stats)
    
    try:
        with ProcessPoolExecutor(max_workers=CONFIG['num_threads']) as executor:
            futures = []
            for tid in range(CONFIG['num_threads']):
                start = positions[tid]
                end = CONFIG['start_range'] + (tid + 1) * chunk_size - 1 if tid < CONFIG['num_threads'] - 1 else CONFIG['end_range']
                futures.append(executor.submit(process_chunk, tid, start, end, result_queue, total_stats))
            
            active_threads = CONFIG['num_threads']
            last_save_time = time.time()
            last_update_time = time.time()
            
            while active_threads > 0:
                if not result_queue.empty():
                    msg_type, data = result_queue.get()
                    
                    if msg_type == 'found':
                        tid, key = data
                        print(f"\n{Fore.GREEN}🎉 Найден ключ в потоке {tid}: 0x{key}{Style.RESET_ALL}")
                        for future in futures:
                            future.cancel()
                        if os.path.exists(CONFIG['state_file']):
                            os.remove(CONFIG['state_file'])
                        return
                    
                    elif msg_type == 'progress':
                        tid = data['thread_id']
                        last_keys[tid] = data['last_key']
                        positions[tid] = data['current']
                        
                        # Обновляем статистику
                        total_stats['actually_checked'] += data['local_checked']
                        total_stats['total_processed'] += data['local_processed']
                        total_stats['percent'] = calculate_percentage(positions)
                    
                    elif msg_type == 'done':
                        active_threads -= 1
                
                current_time = time.time()
                if current_time - last_update_time >= CONFIG['update_interval']:
                    print_status(total_stats, dict(last_keys))
                    last_update_time = current_time
                
                if current_time - last_save_time > 300:  # Сохраняем каждые 5 минут
                    if save_state(positions, total_stats):
                        last_save_time = current_time
                        print(f"\n{Fore.GREEN}Автосохранение выполнено.{Style.RESET_ALL}")
                
                time.sleep(0.1)
            
            print(f"\n{Fore.YELLOW}Поиск завершен. Ключ не найден.{Style.RESET_ALL}")
            if os.path.exists(CONFIG['state_file']):
                os.remove(CONFIG['state_file'])
    
    except Exception as e:
        print(f"\n{Fore.RED}Ошибка: {str(e)}{Style.RESET_ALL}")
        save_state(positions, total_stats)

if __name__ == "__main__":
    freeze_support()
    main()