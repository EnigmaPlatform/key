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

# Инициализация colorama
init()

# Конфигурация
CONFIG = {
    "target_hash": "f6f5431d25bbf7b12e8add9af5e3475c44a0a5b8",
    "start_range": 0x600000000000000000,
    "end_range": 0x6f0000000000000000,
    "num_threads": max(8, os.cpu_count() + 4),
    "update_interval": 2.0,
    "state_file": "search_state.json",
    "backup_interval": 300  # 5 минут в секундах
}

class JumpCounter:
    def __init__(self, manager):
        self.total_jumps = manager.Value('i', 0)
        self.jump_stats = manager.dict({
            'small': manager.Value('i', 0),
            'medium': manager.Value('i', 0),
            'large': manager.Value('i', 0),
            'huge': manager.Value('i', 0)
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

def calculate_jump(key_hex, thread_id, jump_counter):
    """Определение размера прыжка по строгому приоритету"""
    original = int(key_hex, 16)
    last_17 = key_hex[-17:]
    
    max_repeat = detect_repeats_numba(last_17)
    
    # Строгий приоритет прыжков
    if max_repeat >= 14:
        jump_size = 0x1000000000000  # 4.2B (huge)
        jump_type = 'huge'
    elif max_repeat >= 10:
        jump_size = 0x1000000000    # 16M (large)
        jump_type = 'large'
    elif max_repeat >= 7:
        jump_size = 0x1000000      # 65K (medium)
        jump_type = 'medium'
    elif max_repeat >= 4:
        jump_size = 0x100        # 256 (small)
        jump_type = 'small'
    else:
        return original + 1      # Обычный инкремент
    
    jump_counter.increment(jump_type)
    new_pos = original + jump_size
    
    if jump_size >= 0x100:
        print(f"{Fore.MAGENTA}[Поток {thread_id}] Прыжок на {jump_size:,} ключей ({jump_type}): "
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
        
        # Сначала пытаемся сделать прыжок
        prev_current = current
        current = calculate_jump(key_hex, thread_id, jump_counter)
        if current > prev_current + 1:
            local_jumps += 1
            continue
        
        # Проверяем ключ только если не было прыжка
        try:
            key_bytes = bytes.fromhex(key_hex)
            pub_key = coincurve.PublicKey.from_secret(key_bytes).format(compressed=True)
            h = hashlib.new('ripemd160', hashlib.sha256(pub_key).digest()).hexdigest()
            
            if h == CONFIG['target_hash']:
                result_queue.put(('found', (thread_id, key_hex)))
                return
            
            processed += 1
            
            # Обновляем статистику
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
            print(f"{Fore.RED}[Поток {thread_id}] Ошибка проверки ключа: {e}{Style.RESET_ALL}")
        
        current += 1
    
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
    """Загрузка состояния из файла с улучшенной обработкой ошибок"""
    if not os.path.exists(CONFIG['state_file']):
        return None
        
    print(f"\n{Fore.YELLOW}Обнаружен файл сохранения: {CONFIG['state_file']}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Последнее изменение: {time.ctime(os.path.getmtime(CONFIG['state_file']))}{Style.RESET_ALL}")
    
    try:
        with open(CONFIG['state_file'], 'r') as f:
            state = json.load(f)
        
        print(f"\n{Fore.CYAN}=== ИНФОРМАЦИЯ О СОХРАНЕНИИ ===")
        print(f"Прогресс: {state.get('percent', 0):.18f}%")
        print(f"Обработано ключей: {state.get('processed', 0):,}")
        print(f"Последние позиции потоков:{Style.RESET_ALL}")
        for tid, pos in enumerate(state.get('positions', [])):
            print(f"  Поток {tid}: 0x{f'{int(pos, 16):x}'[-18:]}")
        
        while True:
            choice = input("\nХотите продолжить с этого места? (y/n/delete): ").strip().lower()
            if choice == 'y':
                print(f"{Fore.GREEN}Состояние загружено{Style.RESET_ALL}")
                return state
            elif choice == 'n':
                print(f"{Fore.YELLOW}Начинаем новый поиск{Style.RESET_ALL}")
                return None
            elif choice == 'delete':
                os.remove(CONFIG['state_file'])
                print(f"{Fore.GREEN}Файл сохранения удален. Начинаем новый поиск.{Style.RESET_ALL}")
                return None
            else:
                print(f"{Fore.RED}Пожалуйста, введите 'y', 'n' или 'delete'{Style.RESET_ALL}")
                
    except Exception as e:
        print(f"{Fore.RED}Ошибка загрузки состояния: {e}{Style.RESET_ALL}")
        return None

def save_state(positions, processed, jump_counter):
    """Сохранение текущего состояния с улучшенной обработкой"""
    temp_file = CONFIG['state_file'] + ".tmp"
    try:
        state_data = {
            'positions': [f"{pos:064x}" for pos in positions],
            'processed': processed.value if hasattr(processed, 'value') else processed,
            'config': CONFIG,
            'jump_stats': {
                'total': jump_counter.total_jumps.value,
                'small': jump_counter.jump_stats['small'].value,
                'medium': jump_counter.jump_stats['medium'].value,
                'large': jump_counter.jump_stats['large'].value,
                'huge': jump_counter.jump_stats['huge'].value
            },
            'timestamp': time.time(),
            'percent': calculate_percentage(positions)
        }
        
        with open(temp_file, 'w') as f:
            json.dump(state_data, f, indent=2)
        
        with open(temp_file, 'r') as f:
            json.load(f)
        
        if os.path.exists(CONFIG['state_file']):
            os.remove(CONFIG['state_file'])
        os.rename(temp_file, CONFIG['state_file'])
        
        return True
    except Exception as e:
        print(f"{Fore.RED}Ошибка сохранения состояния: {e}{Style.RESET_ALL}")
        if os.path.exists(temp_file):
            os.remove(temp_file)
        return False

def calculate_percentage(positions):
    """Вычисление общего прогресса с проверкой диапазона"""
    total_range = CONFIG['end_range'] - CONFIG['start_range']
    if total_range <= 0:
        return 0.0
    progress = sum(pos - CONFIG['start_range'] for pos in positions) / total_range
    return (progress / CONFIG['num_threads']) * 100

def print_status(stats, last_keys, jump_counter):
    """Вывод информации о статусе поиска с улучшенным форматированием"""
    os.system('cls' if os.name == 'nt' else 'clear')
    
    print(f"{Fore.CYAN}=== ИНФОРМАЦИЯ О ПОИСКЕ ==={Style.RESET_ALL}")
    print(f"Потоков: {CONFIG['num_threads']} | Скорость: {stats['speed']:,.0f} ключей/сек")
    print(f"Обработано: {stats['processed']:,} ключей | Прогресс: {stats['percent']:.18f}%")
    print(f"Прошло времени: {stats['elapsed']/60:.1f} минут")
    
    print(f"\n{Fore.YELLOW}СТАТИСТИКА ПРЫЖКОВ:{Style.RESET_ALL}")
    print(f"Всего прыжков: {jump_counter.total_jumps.value:,}")
    print(f"  Малые (256): {jump_counter.jump_stats['small'].value:,}")
    print(f"  Средние (65K): {jump_counter.jump_stats['medium'].value:,}")
    print(f"  Большие (16M): {jump_counter.jump_stats['large'].value:,}")
    print(f"  Огромные (4.2G): {jump_counter.jump_stats['huge'].value:,}")
    
    print(f"\n{Fore.YELLOW}ПОСЛЕДНИЕ ПРОВЕРЕННЫЕ КЛЮЧИ:{Style.RESET_ALL}")
    for tid in sorted(last_keys.keys()):
        print(f"Поток {tid:2}: 0x{last_keys[tid][-18:]}")
    
    if stats['percent'] > 0:
        remaining = (100 - stats['percent']) * stats['elapsed'] / stats['percent']
        print(f"\n{Fore.MAGENTA}Осталось времени: ~{remaining/3600:.1f} часов{Style.RESET_ALL}")
        print(f"Примерное время завершения: {time.ctime(time.time() + remaining)}")
    
    print(f"\n{Fore.WHITE}Для выхода нажмите Ctrl+C (состояние будет сохранено){Style.RESET_ALL}")

def setup_signal_handlers(positions, processed, jump_counter):
    """Установка обработчиков сигналов с улучшенной обработкой"""
    def signal_handler(sig, frame):
        print(f"\n{Fore.YELLOW}Получен сигнал завершения. Сохраняем состояние...{Style.RESET_ALL}")
        save_state(positions, processed, jump_counter)
        print(f"{Fore.GREEN}Сохранение завершено. Выход.{Style.RESET_ALL}")
        os._exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

def main():
    """Главная функция выполнения с полной инициализацией"""
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

