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
    "start_range": 0x349b84b6430a5c4ef9,
    "end_range": 0x349b84b6431a6c4ef9,
    "num_threads": max(8, os.cpu_count() + 6),
    "update_interval": 2.0,
    "state_file": "search_state.json"
}

@jit(nopython=True)
def detect_repeats_numba(key_part):
    """Проверка повторений в последних 17 символах"""
    max_repeats = 1
    current = 1
    for i in range(1, len(key_part)):
        if key_part[i] == key_part[i-1]:
            current += 1
            if current > max_repeats:
                max_repeats = current
                if max_repeats >= 14:
                    return max_repeats
        else:
            current = 1
    return max_repeats

def calculate_jump(key_hex, thread_id):
    """Агрессивные прыжки на основе повторений"""
    original = int(key_hex, 16)
    last_17 = key_hex[-17:]
    
    max_repeat = detect_repeats_numba(last_17)
    
    if max_repeat >= 14:
        jump_size = 0x100000000  # 4,294,967,296 ключей
    elif max_repeat >= 10:
        jump_size = 0x1000000    # 16,777,216 ключей
    elif max_repeat >= 7:
        jump_size = 0x10000      # 65,536 ключей
    elif max_repeat >= 4:
        jump_size = 0x100        # 256 ключей
    else:
        return original + 1      # Обычный инкремент
    
    new_pos = original + jump_size
    
    if jump_size >= 0x1000000:
        print(f"{Fore.MAGENTA}[Поток {thread_id}] Прыжок на {jump_size:,} ключей: "
              f"0x{key_hex[-18:]} → 0x{f'{new_pos:x}'[-18:]}{Style.RESET_ALL}")
    
    return min(new_pos, CONFIG['end_range'])

def process_chunk(thread_id, start, end, result_queue):
    """Обработка диапазона ключей с прыжками"""
    current = start
    chunk_size = end - start
    chunk_start_time = time.time()
    last_update = chunk_start_time
    processed = 0
    
    while current <= end:
        key_hex = f"{current:064x}"
        key_last_17 = key_hex[-17:]
        
        if detect_repeats_numba(key_last_17) < 4:
            try:
                key_bytes = bytes.fromhex(key_hex)
                pub_key = coincurve.PublicKey.from_secret(key_bytes).format(compressed=True)
                h = hashlib.new('ripemd160', hashlib.sha256(pub_key).digest()).hexdigest()
                
                if h == CONFIG['target_hash']:
                    result_queue.put(('found', (thread_id, key_hex)))
                    return
                
                processed += 1
                
                now = time.time()
                if now - last_update >= CONFIG['update_interval']:
                    elapsed = now - chunk_start_time
                    speed = processed / elapsed
                    percent = (current - start) / chunk_size * 100
                    
                    result_queue.put(('progress', {
                        'thread_id': thread_id,
                        'current': current,
                        'last_key': key_hex,
                        'processed': processed,
                        'speed': speed,
                        'percent': percent,
                        'elapsed': elapsed
                    }))
                    last_update = now
            except Exception:
                pass
        
        current = calculate_jump(key_hex, thread_id)
    
    result_queue.put(('done', thread_id))

def run_benchmark():
    """Запуск бенчмарка производительности"""
    print(f"\n{Fore.CYAN}=== ЗАПУСК БЕНЧМАРКА ==={Style.RESET_ALL}")
    
    test_key = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
    start = time.time()
    count = 0
    while time.time() - start < 2.0:
        key_bytes = bytes.fromhex(test_key)
        pub_key = coincurve.PublicKey.from_secret(key_bytes).format(compressed=True)
        h = hashlib.new('ripemd160', hashlib.sha256(pub_key).digest())
        count += 1
    speed = count / 2.0
    
    print(f"{Fore.GREEN}Скорость одного потока: {speed:,.0f} ключей/сек{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Ожидаемая скорость ({CONFIG['num_threads']} потоков): ~{speed * CONFIG['num_threads']:,.0f} ключей/сек{Style.RESET_ALL}")
    
    return {'speed': speed}

def load_state():
    """Загрузка состояния из файла"""
    if not os.path.exists(CONFIG['state_file']):
        return None
        
    print(f"\n{Fore.YELLOW}Обнаружен файл сохранения: {CONFIG['state_file']}{Style.RESET_ALL}")
    choice = input("Хотите продолжить с предыдущего места? (y/n): ").strip().lower()
    if choice != 'y':
        return None
    
    try:
        with open(CONFIG['state_file'], 'r') as f:
            state = json.load(f)
        print(f"{Fore.GREEN}Состояние загружено{Style.RESET_ALL}")
        return state
    except Exception as e:
        print(f"{Fore.RED}Ошибка загрузки состояния: {e}{Style.RESET_ALL}")
        return None

def save_state(positions, processed):
    """Сохранение текущего состояния"""
    try:
        with open(CONFIG['state_file'], 'w') as f:
            json.dump({
                'positions': positions,
                'processed': processed,
                'config': CONFIG
            }, f, indent=2)
        return True
    except Exception as e:
        print(f"{Fore.RED}Ошибка сохранения состояния: {e}{Style.RESET_ALL}")
        return False

def print_status(stats, last_keys):
    """Вывод информации о статусе поиска"""
    os.system('cls' if os.name == 'nt' else 'clear')
    
    print(f"{Fore.CYAN}=== ИНФОРМАЦИЯ О ПОИСКЕ ==={Style.RESET_ALL}")
    print(f"Потоков: {CONFIG['num_threads']} | Скорость: {stats['speed']:,.0f} ключей/сек")
    print(f"Обработано: {stats['processed']:,} ключей | Прогресс: {stats['percent']:.18f}%")
    print(f"Прошло времени: {stats['elapsed']/60:.1f} минут")
    
    print(f"\n{Fore.YELLOW}ПОСЛЕДНИЕ ПРОВЕРЕННЫЕ КЛЮЧИ:{Style.RESET_ALL}")
    for tid in sorted(last_keys.keys()):
        print(f"Поток {tid:2}: 0x{last_keys[tid][-18:]}")
    
    if stats['percent'] > 0:
        remaining = (100 - stats['percent']) * stats['elapsed'] / stats['percent']
        print(f"\n{Fore.MAGENTA}Осталось времени: ~{remaining/3600:.1f} часов{Style.RESET_ALL}")
        print(f"Примерное время завершения: {time.ctime(time.time() + remaining)}")
    
    print(f"\n{Fore.WHITE}Для выхода нажмите Ctrl+C (состояние будет сохранено){Style.RESET_ALL}")

def main():
    """Главная функция выполнения"""
    benchmark = run_benchmark()
    state = load_state()
    
    manager = Manager()
    result_queue = manager.Queue()
    last_keys = manager.dict()
    total_processed = manager.Value('i', 0)
    total_speed = manager.Value('f', 0.0)
    
    # Инициализация позиций потоков
    chunk_size = (CONFIG['end_range'] - CONFIG['start_range']) // CONFIG['num_threads']
    positions = []
    for tid in range(CONFIG['num_threads']):
        if state and 'positions' in state and tid < len(state['positions']):
            positions.append(state['positions'][tid])
        else:
            positions.append(CONFIG['start_range'] + tid * chunk_size)
        last_keys[tid] = f"{positions[tid]:064x}"  # Инициализация последнего ключа
    
    stats = {
        'processed': state['processed'] if state else 0,
        'speed': 0,
        'percent': 0,
        'elapsed': 0
    }
    
    try:
        with ProcessPoolExecutor(max_workers=CONFIG['num_threads']) as executor:
            futures = []
            for tid in range(CONFIG['num_threads']):
                start = positions[tid]
                end = CONFIG['start_range'] + (tid + 1) * chunk_size - 1 if tid < CONFIG['num_threads'] - 1 else CONFIG['end_range']
                futures.append(executor.submit(process_chunk, tid, start, end, result_queue))
            
            active_threads = CONFIG['num_threads']
            last_save_time = time.time()
            
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
                        
                        # Рассчет общей скорости
                        if data['elapsed'] > 0:
                            current_speed = total_processed.value / data['elapsed']
                            total_speed.value = current_speed
                        
                        stats.update({
                            'processed': total_processed.value,
                            'speed': total_speed.value,
                            'percent': data['percent'],
                            'elapsed': data['elapsed']
                        })
                    
                    elif msg_type == 'done':
                        active_threads -= 1
                
                # Обновление статуса
                if time.time() - last_save_time >= CONFIG['update_interval']:
                    print_status(stats, dict(last_keys))
                
                # Автосохранение каждые 5 минут
                if time.time() - last_save_time > 300:
                    if save_state([last_keys[tid] for tid in range(CONFIG['num_threads'])], total_processed.value):
                        last_save_time = time.time()
                
                time.sleep(0.1)
            
            print(f"\n{Fore.YELLOW}Поиск завершен. Ключ не найден.{Style.RESET_ALL}")
            if os.path.exists(CONFIG['state_file']):
                os.remove(CONFIG['state_file'])
    
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Сохранение состояния перед выходом...{Style.RESET_ALL}")
        save_state([last_keys[tid] for tid in range(CONFIG['num_threads'])], total_processed.value)
        print(f"{Fore.GREEN}Сохранено текущее состояние в {CONFIG['state_file']}{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}Ошибка: {str(e)}{Style.RESET_ALL}")
        traceback.print_exc()
        save_state([last_keys[tid] for tid in range(CONFIG['num_threads'])], total_processed.value)

if __name__ == "__main__":
    freeze_support()
    main()
