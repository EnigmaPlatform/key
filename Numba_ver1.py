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
import numpy as np
from sklearn.cluster import KMeans
import shutil
from datetime import datetime

# Инициализация colorama
init()

# Конфигурация
CONFIG = {
    "target_hash": "5db8cda53a6a002db10365967d7f85d19e171b10",
    "start_range": 0x348b84b643006c4ef1,
    "end_range": 0x349b84b6431a6c4ef1,
    "num_threads": max(8, os.cpu_count() + 4),
    "update_interval": 2.0,
    "state_file": "search_state.json",
    "backup_dir": "backups",
    "max_backups": 5,
    "backup_interval": 300,
    "adaptive_learning": True
}

class BackupManager:
    def __init__(self):
        os.makedirs(CONFIG['backup_dir'], exist_ok=True)
        
    def create_backup(self, state_data):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = os.path.join(CONFIG['backup_dir'], f"backup_{timestamp}.json")
        
        try:
            with open(backup_file, 'w') as f:
                json.dump(state_data, f, indent=2)
            
            backups = sorted(
                [f for f in os.listdir(CONFIG['backup_dir']) if f.startswith('backup_')],
                reverse=True
            )
            for old_backup in backups[CONFIG['max_backups']:]:
                os.remove(os.path.join(CONFIG['backup_dir'], old_backup))
                
            return True
        except Exception as e:
            print(f"{Fore.RED}Ошибка создания бэкапа: {e}{Style.RESET_ALL}")
            return False

class AdaptiveSystem:
    def __init__(self):
        self.pattern_stats = []
        self.jump_effectiveness = []
        self.kmeans = KMeans(n_clusters=3)
        self.last_analysis = 0
        
    def add_pattern(self, pattern_type, jump_size, speed_gain):
        self.pattern_stats.append({
            'type': pattern_type,
            'jump_size': jump_size,
            'speed_gain': speed_gain,
            'timestamp': time.time()
        })
        
    def analyze_patterns(self):
        if len(self.pattern_stats) < 50 or time.time() - self.last_analysis < 600:
            return None
            
        try:
            X = np.array([
                [stat['jump_size'], stat['speed_gain']] 
                for stat in self.pattern_stats[-1000:]
            ])
            
            self.kmeans.fit(X)
            best_cluster = np.argmax(self.kmeans.cluster_centers_[:, 1])
            optimal_jump = int(self.kmeans.cluster_centers_[best_cluster][0])
            
            self.last_analysis = time.time()
            return optimal_jump
        except Exception as e:
            print(f"{Fore.RED}Ошибка анализа паттернов: {e}{Style.RESET_ALL}")
            return None

class JumpCounter:
    def __init__(self, manager):
        self.total_jumps = manager.Value('i', 0)
        self.jump_stats = manager.dict({
            'high_priority': manager.Value('i', 0),
            'mid_priority': manager.Value('i', 0),
            'low_priority': manager.Value('i', 0),
            'digit_blocks': manager.Value('i', 0),
            'alpha_blocks': manager.Value('i', 0),
            'sequences': manager.Value('i', 0)
        })
        self.lock = manager.Lock()
        self.adaptive = AdaptiveSystem() if CONFIG['adaptive_learning'] else None
    
    def increment(self, jump_type, jump_size, speed_gain):
        with self.lock:
            self.total_jumps.value += 1
            if jump_type in self.jump_stats:
                self.jump_stats[jump_type].value += 1
            if self.adaptive:
                self.adaptive.add_pattern(jump_type, jump_size, speed_gain)

@jit(nopython=True)
def detect_repeats_numba(key_part):
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

def analyze_17_chars(key_hex):
    last_17 = key_hex[-17:] if len(key_hex) >= 17 else key_hex.zfill(17)[-17:]
    
    zones = {
        'high_priority': last_17[:6],
        'mid_priority': last_17[6:12],
        'low_priority': last_17[12:]
    }
    
    checks = {
        'all_digits': all(c.isdigit() for c in last_17),
        'all_alpha': all(c.isalpha() for c in last_17),
        'repeats': detect_repeats_numba(last_17),
        'sequences': detect_sequences(last_17)
    }
    
    return zones, checks

def detect_sequences(zone):
    if len(zone) < 4:
        return 0
        
    seq_types = []
    for i in range(len(zone)-3):
        if zone[i:i+4].isdigit():
            if ord(zone[i+1]) == ord(zone[i])+1 and ord(zone[i+2]) == ord(zone[i])+2:
                seq_types.append('digit_inc')
            elif ord(zone[i+1]) == ord(zone[i])-1 and ord(zone[i+2]) == ord(zone[i])-2:
                seq_types.append('digit_dec')
        elif zone[i:i+4].isalpha():
            if ord(zone[i+1].lower()) == ord(zone[i].lower())+1 and ord(zone[i+2].lower()) == ord(zone[i].lower())+2:
                seq_types.append('alpha_inc')
            elif ord(zone[i+1].lower()) == ord(zone[i].lower())-1 and ord(zone[i+2].lower()) == ord(zone[i].lower())-2:
                seq_types.append('alpha_dec')
    
    return len(seq_types)

def calculate_jump(key_hex, thread_id, jump_counter):
    original = int(key_hex, 16)
    zones, checks = analyze_17_chars(key_hex)
    
    # 1. Высокоприоритетные паттерны
    hp_pattern = detect_high_priority_pattern(zones['high_priority'])
    if hp_pattern:
        jump_size = 0x1000000000
        jump_type = 'high_priority'
        speed_gain = jump_size / 1000
        jump_counter.increment(jump_type, jump_size, speed_gain)
        new_pos = original + jump_size
        print(f"{Fore.CYAN}[Поток {thread_id}] HIGH прыжок {jump_size:,} ({hp_pattern}){Style.RESET_ALL}")
        return min(new_pos, CONFIG['end_range'])
    
    # 2. Среднеприоритетные паттерны
    mp_pattern = detect_mid_priority_pattern(zones['mid_priority'])
    if mp_pattern:
        jump_size = 0x1000000
        jump_type = 'mid_priority'
        speed_gain = jump_size / 100
        jump_counter.increment(jump_type, jump_size, speed_gain)
        new_pos = original + jump_size
        print(f"{Fore.BLUE}[Поток {thread_id}] MID прыжок {jump_size:,} ({mp_pattern}){Style.RESET_ALL}")
        return min(new_pos, CONFIG['end_range'])
    
    # 3. Блоки цифр/букв
    if checks['all_digits']:
        jump_size = 0x10000
        jump_type = 'digit_blocks'
        speed_gain = jump_size / 10
        jump_counter.increment(jump_type, jump_size, speed_gain)
        return original + jump_size
    elif checks['all_alpha']:
        jump_size = 0x1000
        jump_type = 'alpha_blocks'
        speed_gain = jump_size / 5
        jump_counter.increment(jump_type, jump_size, speed_gain)
        return original + jump_size
    
    # 4. Последовательности
    if checks['sequences'] > 0:
        jump_size = 0x100 * checks['sequences']
        jump_type = 'sequences'
        speed_gain = jump_size * 2
        jump_counter.increment(jump_type, jump_size, speed_gain)
        return original + jump_size
    
    # 5. Повторы в младших разрядах
    if checks['repeats'] >= 4:
        jump_size = 0x10 ** checks['repeats']
        jump_type = 'low_priority'
        speed_gain = jump_size
        jump_counter.increment(jump_type, jump_size, speed_gain)
        return original + jump_size
    
    return original + 1

def detect_high_priority_pattern(zone):
    if detect_repeats_numba(zone) >= 4:
        return 'high_repeat'
    if len(zone) >= 4 and zone[:2] == zone[2:4]:
        return 'alternating'
    if zone == zone[::-1]:
        return 'palindrome'
    return None

def detect_mid_priority_pattern(zone):
    if detect_sequences(zone) >= 2:
        return 'sequence'
    if len(zone) >= 4 and any(c.isdigit() for c in zone) and any(c.isalpha() for c in zone):
        return 'mixed'
    return None

def process_chunk(thread_id, start, end, result_queue, jump_counter):
    current = start
    chunk_size = end - start
    chunk_start_time = time.time()
    last_update = chunk_start_time
    actually_checked = 0  # Счетчик реально проверенных ключей
    total_processed = 0   # Счетчик всех обработанных ключей (включая пропущенные)
    local_jumps = 0
    total_operations = 0
    
    while current <= end:
        key_hex = f"{current:064x}"
        total_operations += 1
        
        prev_current = current
        current = calculate_jump(key_hex, thread_id, jump_counter)
        
        # Учитываем прыжки
        if current > prev_current + 1:
            jump_size = current - prev_current
            total_processed += jump_size
            local_jumps += 1
            result_queue.put(('progress', {
                'thread_id': thread_id,
                'current': current,
                'last_key': key_hex,
                'actually_checked': actually_checked,
                'total_processed': total_processed,
                'operations': total_operations,
                'percent': (current - start) / chunk_size * 100,
                'elapsed': time.time() - chunk_start_time,
                'local_jumps': local_jumps
            }))
            continue
        
        try:
            key_bytes = bytes.fromhex(key_hex)
            pub_key = coincurve.PublicKey.from_secret(key_bytes).format(compressed=True)
            h = hashlib.new('ripemd160', hashlib.sha256(pub_key).digest()).hexdigest()
            
            if h == CONFIG['target_hash']:
                result_queue.put(('found', (thread_id, key_hex)))
                return
            
            actually_checked += 1
            total_processed += 1
        except Exception as e:
            print(f"{Fore.RED}[Поток {thread_id}] Ошибка: {e}{Style.RESET_ALL}")
            total_processed += 1
        
        now = time.time()
        if now - last_update >= CONFIG['update_interval']:
            result_queue.put(('progress', {
                'thread_id': thread_id,
                'current': current,
                'last_key': key_hex,
                'actually_checked': actually_checked,
                'total_processed': total_processed,
                'operations': total_operations,
                'percent': (current - start) / chunk_size * 100,
                'elapsed': now - chunk_start_time,
                'local_jumps': local_jumps
            }))
            last_update = now
        
        current += 1
    
    result_queue.put(('done', thread_id))

def print_status(stats, last_keys, jump_counter):
    os.system('cls' if os.name == 'nt' else 'clear')
    
    actual_speed = stats['total_processed'] / stats['elapsed'] if stats['elapsed'] > 0 else 0
    check_speed = stats['actually_checked'] / stats['elapsed'] if stats['elapsed'] > 0 else 0
    ops_speed = stats['operations'] / stats['elapsed'] if stats['elapsed'] > 0 else 0
    
    print(f"{Fore.CYAN}=== ИНФОРМАЦИЯ О ПОИСКЕ ==={Style.RESET_ALL}")
    print(f"Потоков: {CONFIG['num_threads']} | Скорость: {actual_speed:,.0f} ключ/сек (всего)")
    print(f"Проверок: {check_speed:,.0f} ключ/сек | Операций: {ops_speed:,.0f} опер/сек")
    print(f"Проверено: {stats['actually_checked']:,} | Всего: {stats['total_processed']:,} | Прогресс: {stats['percent']:.8f}%")
    print(f"Прошло времени: {stats['elapsed']/60:.1f} минут")
    
    print(f"\n{Fore.YELLOW}СТАТИСТИКА ПРЫЖКОВ:{Style.RESET_ALL}")
    print(f"Всего прыжков: {jump_counter.total_jumps.value:,}")
    print(f"  Высокий приоритет: {jump_counter.jump_stats['high_priority'].value:,}")
    print(f"  Средний приоритет: {jump_counter.jump_stats['mid_priority'].value:,}")
    print(f"  Низкий приоритет: {jump_counter.jump_stats['low_priority'].value:,}")
    print(f"  Блоки цифр: {jump_counter.jump_stats['digit_blocks'].value:,}")
    print(f"  Блоки букв: {jump_counter.jump_stats['alpha_blocks'].value:,}")
    print(f"  Последовательности: {jump_counter.jump_stats['sequences'].value:,}")
    
    print(f"\n{Fore.YELLOW}ПОСЛЕДНИЕ КЛЮЧИ:{Style.RESET_ALL}")
    for tid in sorted(last_keys.keys()):
        print(f"Поток {tid:2}: 0x{last_keys[tid][-18:]}")
    
    if stats['percent'] > 0 and stats['percent'] < 100:
        remaining = (100 - stats['percent']) * stats['elapsed'] / stats['percent']
        print(f"\n{Fore.MAGENTA}Осталось: ~{remaining/3600:.1f} часов | Завершение: {time.ctime(time.time() + remaining)}{Style.RESET_ALL}")
    
    if CONFIG['adaptive_learning'] and jump_counter.adaptive:
        optimal_jump = jump_counter.adaptive.analyze_patterns()
        if optimal_jump:
            print(f"\n{Fore.GREEN}Адаптивная система: оптимальный прыжок ~{optimal_jump:,}{Style.RESET_ALL}")

def run_benchmark():
    print(f"\n{Fore.CYAN}=== БЕНЧМАРК ==={Style.RESET_ALL}")
    
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
    if not os.path.exists(CONFIG['state_file']):
        return None
        
    print(f"\n{Fore.YELLOW}Найден файл состояния: {CONFIG['state_file']}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Последнее изменение: {time.ctime(os.path.getmtime(CONFIG['state_file']))}{Style.RESET_ALL}")
    
    try:
        with open(CONFIG['state_file'], 'r') as f:
            state = json.load(f)
        
        print(f"\n{Fore.CYAN}=== СОХРАНЕННОЕ СОСТОЯНИЕ ===")
        print(f"Прогресс: {state.get('percent', 0):.8f}%")
        print(f"Проверено: {state.get('actually_checked', 0):,} ключей")
        print(f"Всего обработано: {state.get('total_processed', 0):,} ключей")
        print(f"Прыжков: {state.get('total_jumps', 0):,}")
        print(f"Позиции потоков:{Style.RESET_ALL}")
        for tid, pos in enumerate(state.get('positions', [])):
            print(f"  Поток {tid}: 0x{f'{int(pos, 16):x}'[-18:]}")
        
        while True:
            choice = input("\nПродолжить (y), начать заново (n) или удалить (d): ").lower()
            if choice == 'y':
                return state
            elif choice == 'n':
                return None
            elif choice == 'd':
                os.remove(CONFIG['state_file'])
                print(f"{Fore.GREEN}Файл состояния удален.{Style.RESET_ALL}")
                return None
            else:
                print(f"{Fore.RED}Введите y, n или d{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Ошибка загрузки: {e}{Style.RESET_ALL}")
        return None

def save_state(positions, stats, jump_counter):
    backup_mgr = BackupManager()
    temp_file = CONFIG['state_file'] + ".tmp"
    
    try:
        state_data = {
            'positions': [f"{pos:064x}" for pos in positions],
            'actually_checked': stats['actually_checked'].value if hasattr(stats['actually_checked'], 'value') else stats['actually_checked'],
            'total_processed': stats['total_processed'].value if hasattr(stats['total_processed'], 'value') else stats['total_processed'],
            'total_jumps': jump_counter.total_jumps.value,
            'jump_stats': {k: v.value for k, v in jump_counter.jump_stats.items()},
            'timestamp': time.time(),
            'percent': calculate_percentage(positions),
            'config': CONFIG
        }
        
        with open(temp_file, 'w') as f:
            json.dump(state_data, f, indent=2)
        
        with open(temp_file, 'r') as f:
            json.load(f)
        
        backup_mgr.create_backup(state_data)
        
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

def setup_signal_handlers(positions, stats, jump_counter):
    def signal_handler(sig, frame):
        print(f"\n{Fore.YELLOW}Сохранение состояния...{Style.RESET_ALL}")
        save_state(positions, stats, jump_counter)
        print(f"{Fore.GREEN}Сохранено. Выход.{Style.RESET_ALL}")
        os._exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

def main():
    benchmark = run_benchmark()
    state = load_state()
    
    manager = Manager()
    result_queue = manager.Queue()
    last_keys = manager.dict()
    
    # Инициализация статистики
    stats = {
        'actually_checked': manager.Value('i', state['actually_checked'] if state else 0),
        'total_processed': manager.Value('i', state['total_processed'] if state else 0),
        'operations': manager.Value('i', 0),
        'percent': 0.0,
        'elapsed': 0.0,
        'speed': 0.0
    }
    
    jump_counter = JumpCounter(manager)
    backup_mgr = BackupManager()
    
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
    
    start_time = time.time()
    setup_signal_handlers(positions, stats, jump_counter)
    
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
                        print(f"\n{Fore.GREEN}🎉 Найден ключ в потоке {tid}: 0x{key}{Style.RESET_ALL}")
                        for future in futures:
                            future.cancel()
                        if os.path.exists(CONFIG['state_file']):
                            os.remove(CONFIG['state_file'])
                        return
                    
                    elif msg_type == 'progress':
                        tid = data['thread_id']
                        last_keys[tid] = data['last_key']
                        stats['actually_checked'].value += data['actually_checked']
                        stats['total_processed'].value += data['total_processed']
                        stats['operations'].value += data['operations']
                        positions[tid] = data['current']
                        
                        stats.update({
                            'percent': calculate_percentage(positions),
                            'elapsed': time.time() - start_time,
                            'speed': stats['total_processed'].value / (time.time() - start_time) if (time.time() - start_time) > 0 else 0
                        })
                    
                    elif msg_type == 'done':
                        active_threads -= 1
                
                current_time = time.time()
                if current_time - last_update_time >= CONFIG['update_interval']:
                    print_status({
                        'actually_checked': stats['actually_checked'].value,
                        'total_processed': stats['total_processed'].value,
                        'operations': stats['operations'].value,
                        'percent': stats['percent'],
                        'elapsed': stats['elapsed'],
                        'speed': stats['speed']
                    }, dict(last_keys), jump_counter)
                    last_update_time = current_time
                
                if current_time - last_save_time > CONFIG['backup_interval']:
                    if save_state(positions, stats, jump_counter):
                        last_save_time = current_time
                        print(f"\n{Fore.GREEN}Автосохранение выполнено.{Style.RESET_ALL}")
                
                time.sleep(0.1)
            
            print(f"\n{Fore.YELLOW}Поиск завершен. Ключ не найден.{Style.RESET_ALL}")
            if os.path.exists(CONFIG['state_file']):
                os.remove(CONFIG['state_file'])
    
    except Exception as e:
        print(f"\n{Fore.RED}Ошибка: {str(e)}{Style.RESET_ALL}")
        traceback.print_exc()
        save_state(positions, stats, jump_counter)

if __name__ == "__main__":
    freeze_support()
    main()

