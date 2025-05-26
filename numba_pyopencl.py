# -*- coding: utf-8 -*-
import hashlib
import coincurve
from concurrent.futures import ProcessPoolExecutor
import time
import os
import pickle
import sys
from datetime import timedelta
import itertools
from collections import Counter

# Конфигурация
TARGET_HASH = "5db8cda53a6a002db10365967d7f85d19e171b10"
TEST_KEY = "0000000000000000000000000000000000000000000000000000000000000001"
TEST_HASH = "751e76e8199196d454941c45d1b3a323f1433bd6"
START_RANGE = 0x349b84b643196c4ef1  # Начальный диапазон для теста
END_RANGE = 0x349b84b6431a6c4ef1  # Большой диапазон для демонстрации
NUM_THREADS = 12
AUTOSAVE_INTERVAL = 300
PROGRESS_UPDATE_INTERVAL = 1000

# Настройки фильтрации ключей
FILTER_CONFIG = {
    'min_unique_chars': 4,
    'max_repeat_chars': 5,
    'check_common_patterns': True,
    'check_sequential': True,
    'check_symmetric': True,
    'interesting_patterns': [
        '123456789abcdef',
        '1a2b3c4d5e6f',
        'a1b2c3d4e5f6',
        'deadbeef',
        'cafebabe',
        'badc0de'
    ]
}

# Цвета для вывода
COLOR = {
    'red': "\033[91m",
    'green': "\033[92m",
    'yellow': "\033[93m",
    'blue': "\033[94m",
    'cyan': "\033[96m",
    'magenta': "\033[95m",
    'reset': "\033[0m",
    'bold': "\033[1m"
}

class AnalyticsDisplay:
    def __init__(self, num_threads):
        self.num_threads = num_threads
        self.sections = {
            'header': 0,
            'test': 4,
            'progress': 7,
            'threads': 9,
            'stats': 9 + num_threads + 3,
            'reasons': 9 + num_threads + 8,
            'details': 9 + num_threads + 15
        }
        self.thread_lines = list(range(
            self.sections['threads'] + 2,
            self.sections['threads'] + 2 + num_threads
        ))
        self.last_update = time.time()
        
    def init_display(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        print("\033[H")
        
        # Шапка
        self._print_section('header', 
            f"{COLOR['blue']}▄{'▄'*78}▄{COLOR['reset']}\n"
            f"{COLOR['blue']}█{'ПОИСК КРИПТОГРАФИЧЕСКИХ КЛЮЧЕЙ'.center(78)}█{COLOR['reset']}\n"
            f"{COLOR['blue']}▀{'▀'*78}▀{COLOR['reset']}"
        )
        
        # Тест хеширования
        test_passed = run_hash_test()
        status = f"{COLOR['green']}ПРОЙДЕН" if test_passed else f"{COLOR['red']}НЕ ПРОЙДЕН"
        self._print_section('test',
            f"{COLOR['bold']}▌ ТЕСТ ХЕШИРОВАНИЯ: {status}{COLOR['reset']}",
            f"▌ Тестовый ключ: {TEST_KEY}",
            f"▌ Ожидаемый хеш: {TEST_HASH}"
        )
        
        if not test_passed:
            sys.exit(1)
        
        # Прогресс
        self._print_section('progress', 
            f"{COLOR['bold']}▌ ПРОГРЕСС:{COLOR['reset']}",
            f"[{' ' * 20}] 0.00% | 0.0 keys/s"
        )
        
        # Потоки
        self._print_section('threads',
            f"{COLOR['bold']}▌ АКТИВНЫЕ ПОТОКИ:{COLOR['reset']}",
            f"{'ID':<4}{'Текущий ключ':<20}{'Хеш':<22}{'Обработано':>12}{'Скорость':>12}",
            f"{'-'*4:<4}{'-'*20:<20}{'-'*22:<22}{'(ключей)':>12}{'(keys/s)':>12}"
        )
        
        # Статистика
        self._print_section('stats',
            f"{COLOR['bold']}▌ СТАТИСТИКА:{COLOR['reset']}",
            f"Всего обработано: {0:>15}",
            f"Интересных ключей: {0:>13}",
            f"Пропущено ключей: {0:>14}",
            f"Общая скорость: {0:>17} keys/s"
        )
        
        # Причины пропуска
        self._print_section('reasons',
            f"{COLOR['bold']}▌ ПРИЧИНЫ ПРОПУСКА:{COLOR['reset']}",
            f"Повторы символов: {0:>14}",
            f"Последовательности: {0:>11}",
            f"Симметричные комбинации: {0:>6}",
            f"Мало уникальных символов: {0:>8}"
        )
        
        # Детали
        self._print_section('details',
            f"{COLOR['bold']}▌ ДЕТАЛИ ПОИСКА:{COLOR['reset']}",
            f"▌ Диапазон: 0x{START_RANGE:016x} - 0x{END_RANGE:016x}",
            f"▌ Потоков: {NUM_THREADS}",
            f"▌ Фильтр: анализируются последние 17 символов"
        )

    def _print_section(self, name, *lines):
        pos = self.sections[name]
        for i, line in enumerate(lines):
            print(f"\033[{pos+i};0H\033[K{line}", end="")

    def update_progress(self, progress, speed):
        filled = min(int(progress * 20), 20)
        bar = f"[{'#' * filled}{' ' * (20 - filled)}]"
        percent = min(progress * 100, 100)
        self._print_section('progress',
            f"{COLOR['bold']}▌ ПРОГРЕСС:{COLOR['reset']}",
            f"{bar} {percent:.2f}% | {speed:.1f} keys/s"
        )

    def update_thread(self, thread_id, key_hex, current_hash, processed, speed):
        line = self.thread_lines[thread_id]
        short_key = key_hex[46:] if len(key_hex) >= 64 else key_hex
        short_hash = f"{current_hash[:8]}..{current_hash[-6:]}" if current_hash else '...вычисляется...'
        print(f"\033[{line};0H\033[K"
              f"{thread_id:<4}0x{short_key:<18} {short_hash:<20} "
              f"{processed:>12,}{speed:>12.1f}", end="")

    def update_stats(self, total, interesting, skipped, speed):
        self._print_section('stats',
            f"{COLOR['bold']}▌ СТАТИСТИКА:{COLOR['reset']}",
            f"Всего обработано: {total:>15,}",
            f"Интересных ключей: {interesting:>13,}",
            f"Пропущено ключей: {skipped:>14,}",
            f"Общая скорость: {speed:>17,.1f} keys/s"
        )

    def update_reasons(self, reasons):
        self._print_section('reasons',
            f"{COLOR['bold']}▌ ПРИЧИНЫ ПРОПУСКА:{COLOR['reset']}",
            f"Повторы символов: {reasons.get('repeating_chars',0):>14,}",
            f"Последовательности: {reasons.get('sequential',0):>11,}",
            f"Симметричные комбинации: {reasons.get('symmetric',0):>6,}",
            f"Мало уникальных символов: {reasons.get('unique_chars',0):>8,}"
        )

    def show_found(self, key_hex, found_hash):
        self._print_section('details',
            f"{COLOR['green']}▌{' КЛЮЧ НАЙДЕН! ':=^78}▌{COLOR['reset']}",
            f"▌ Приватный ключ: {COLOR['green']}0x{key_hex}{COLOR['reset']}",
            f"▌ Найденный хеш: {found_hash}",
            f"▌ Ожидаемый хеш: {TARGET_HASH}",
            f"{COLOR['green']}▌{'='*78}▌{COLOR['reset']}"
        )

def has_repeating_chars(s, max_repeat):
    return any(sum(1 for _ in group) > max_repeat for _, group in itertools.groupby(s))

def is_sequential(s, direction=1):
    for i in range(1, len(s)):
        if ord(s[i]) - ord(s[i-1]) != direction:
            return False
    return True

def is_symmetric(s):
    return s == s[::-1]

def contains_pattern(s, patterns):
    s_lower = s.lower()
    return any(patt.lower() in s_lower for patt in patterns)

def is_potentially_interesting(key_hex):
    last_17 = key_hex[-17:] if len(key_hex) >= 17 else key_hex
    
    if len(set(last_17)) < FILTER_CONFIG['min_unique_chars']:
        return False
        
    if has_repeating_chars(last_17, FILTER_CONFIG['max_repeat_chars']):
        return False
        
    if FILTER_CONFIG['check_sequential']:
        if is_sequential(last_17, 1) or is_sequential(last_17, -1):
            return False
            
    if FILTER_CONFIG['check_symmetric'] and is_symmetric(last_17):
        return False
        
    if FILTER_CONFIG['check_common_patterns'] and contains_pattern(last_17, FILTER_CONFIG['interesting_patterns']):
        return True
        
    return True

def find_next_interesting(start):
    current = start + 1
    while current <= END_RANGE:
        key_hex = f"{current:064x}"
        if is_potentially_interesting(key_hex):
            return current
        current += 1
    return END_RANGE + 1

def get_skip_reason(key_hex):
    last_17 = key_hex[-17:] if len(key_hex) >= 17 else key_hex
    
    if len(set(last_17)) < FILTER_CONFIG['min_unique_chars']:
        return 'unique_chars'
    if has_repeating_chars(last_17, FILTER_CONFIG['max_repeat_chars']):
        return 'repeating_chars'
    if FILTER_CONFIG['check_sequential'] and (is_sequential(last_17, 1) or is_sequential(last_17, -1)):
        return 'sequential'
    if FILTER_CONFIG['check_symmetric'] and is_symmetric(last_17):
        return 'symmetric'
    return 'other'

def run_hash_test():
    try:
        key_bytes = bytes.fromhex(TEST_KEY)
        pub_key = coincurve.PublicKey.from_secret(key_bytes).format(compressed=True)
        sha256_hash = hashlib.sha256(pub_key).digest()
        ripemd160 = hashlib.new('ripemd160', sha256_hash).hexdigest()
        return ripemd160 == TEST_HASH
    except Exception as e:
        print(f"{COLOR['red']}Ошибка в тесте: {str(e)}{COLOR['reset']}")
        return False

def calculate_speed(start_time, processed):
    elapsed = max(time.time() - start_time, 0.001)
    return processed / elapsed

def worker(thread_id, start, end, initial_state=None):
    state = {
        'processed': 0,
        'skipped_blocks': 0,
        'total_skipped_keys': 0,
        'current': start,
        'last_key': None,
        'start_time': time.time(),
        'last_save': time.time(),
        'last_progress_update': time.time(),
        'blocks': [],
        'interesting_keys': 0,
        'reasons': {
            'repeating_chars': 0,
            'sequential': 0,
            'symmetric': 0,
            'unique_chars': 0
        }
    }
    
    if initial_state:
        state.update(initial_state)
        state['current'] = max(state['current'], start)
    
    current = state['current']
    block_start = current
    
    while current <= end:
        key_hex = f"{current:064x}"
        state['last_key'] = key_hex
        
        if not is_potentially_interesting(key_hex):
            next_interesting = find_next_interesting(current)
            block_size = next_interesting - current
            state['total_skipped_keys'] += block_size
            state['blocks'].append({
                'start': current,
                'end': next_interesting - 1,
                'valid': False,
                'size': block_size,
                'reason': get_skip_reason(key_hex)
            })
            state['skipped_blocks'] += 1
            state['reasons'][get_skip_reason(key_hex)] += block_size
            
            current = next_interesting
            block_start = current
            continue
            
        try:
            key_bytes = bytes.fromhex(key_hex)
            pub_key = coincurve.PublicKey.from_secret(key_bytes).format(compressed=True)
            h = hashlib.new('ripemd160', hashlib.sha256(pub_key).digest().hexdigest())
            
            if h == TARGET_HASH:
                if current > block_start:
                    state['blocks'].append({
                        'start': block_start,
                        'end': current-1,
                        'valid': True,
                        'size': current - block_start
                    })
                
                return {
                    'status': 'found',
                    'key': key_hex,
                    'hash': h,
                    'thread_id': thread_id,
                    'stats': state
                }
            
            state['processed'] += 1
            state['interesting_keys'] += 1
            
            if (state['processed'] % PROGRESS_UPDATE_INTERVAL == 0 or 
                time.time() - state['last_progress_update'] > 1):
                state['last_progress_update'] = time.time()
                return {
                    'status': 'progress',
                    'thread_id': thread_id,
                    'key': key_hex,
                    'hash': h,
                    'stats': state
                }
            
            if time.time() - state['last_save'] > AUTOSAVE_INTERVAL:
                state['current'] = current + 1
                with open(f'progress_thread_{thread_id}.pkl', 'wb') as f:
                    pickle.dump(state, f)
                state['last_save'] = time.time()
                
        except Exception as e:
            print(f"{COLOR['red']}Ошибка в потоке {thread_id}: {str(e)}{COLOR['reset']}")
            current += 1
            continue
        
        current += 1
    
    if current > block_start:
        state['blocks'].append({
            'start': block_start,
            'end': current-1,
            'valid': True,
            'size': current - block_start
        })
    
    return {
        'status': 'completed',
        'thread_id': thread_id,
        'stats': state
    }

def main():
    display = AnalyticsDisplay(NUM_THREADS)
    display.init_display()
    
    # Проверяем и загружаем сохраненные состояния
    initial_states = []
    for i in range(NUM_THREADS):
        try:
            with open(f'progress_thread_{i}.pkl', 'rb') as f:
                state = pickle.load(f)
                if state['current'] >= START_RANGE and state['current'] <= END_RANGE:
                    initial_states.append(state)
                else:
                    initial_states.append(None)
                os.remove(f'progress_thread_{i}.pkl')
        except:
            initial_states.append(None)
    
    # Распределяем диапазоны
    chunk_size = (END_RANGE - START_RANGE) // NUM_THREADS
    ranges = []
    for i in range(NUM_THREADS):
        start = START_RANGE + i * chunk_size
        end = start + chunk_size - 1 if i < NUM_THREADS - 1 else END_RANGE
        ranges.append((i, start, end, initial_states[i]))
    
    start_time = time.time()
    found_key = None
    
    with ProcessPoolExecutor(max_workers=NUM_THREADS) as executor:
        futures = [executor.submit(worker, *args) for args in ranges]
        
        try:
            while True:
                time.sleep(0.2)
                
                total_stats = {
                    'processed': 0,
                    'interesting': 0,
                    'skipped': 0,
                    'reasons': Counter(),
                    'speed': 0
                }
                all_done = True
                
                for i, future in enumerate(futures):
                    if not future.done():
                        all_done = False
                        continue
                        
                    try:
                        result = future.result()
                        if result.get('status') == 'found':
                            found_key = result['key']
                            found_hash = result['hash']
                            display.show_found(found_key, found_hash)
                            break
                            
                        stats = result['stats']
                        total_stats['processed'] += stats['processed']
                        total_stats['interesting'] += stats['interesting_keys']
                        total_stats['skipped'] += stats['total_skipped_keys']
                        total_stats['reasons'] += Counter(stats['reasons'])
                        total_stats['speed'] += calculate_speed(stats['start_time'], stats['processed'])
                        
                        if result.get('status') == 'progress':
                            display.update_thread(
                                result['thread_id'],
                                result['key'],
                                result['hash'],
                                stats['processed'],
                                calculate_speed(stats['start_time'], stats['processed'])
                            )
                            
                    except Exception as e:
                        print(f"{COLOR['red']}Ошибка обработки потока {i}: {str(e)}{COLOR['reset']}")
                
                if found_key:
                    break
                    
                if all_done:
                    break
                
                processed_total = sum(
                    f.result()['stats']['processed'] 
                    for f in futures if f.done()
                )
                range_total = END_RANGE - START_RANGE
                progress = min(processed_total / range_total, 1.0) if range_total > 0 else 0
                
                display.update_progress(progress, total_stats['speed'])
                display.update_stats(
                    total_stats['processed'],
                    total_stats['interesting'],
                    total_stats['skipped'],
                    total_stats['speed']
                )
                display.update_reasons(total_stats['reasons'])
                
        except KeyboardInterrupt:
            display._print_section('details',
                f"{COLOR['yellow']}▌ Поиск остановлен пользователем{COLOR['reset']}",
                "▌ Сохранение состояния потоков..."
            )
            
            for i, future in enumerate(futures):
                if not future.done():
                    continue
                try:
                    result = future.result()
                    if 'stats' in result:
                        with open(f'progress_thread_{i}.pkl', 'wb') as f:
                            pickle.dump(result['stats'], f)
                except:
                    pass
    
    if not found_key:
        display._print_section('details',
            f"{COLOR['yellow']}▌ Поиск завершен. Ключ не найден.{COLOR['reset']}",
            f"▌ Диапазон: 0x{START_RANGE:016x} - 0x{END_RANGE:016x}",
            f"▌ Всего обработано: {total_stats['processed']:,} ключей"
        )

    print(f"\033[{display.sections['details'] + 10};0H")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"{COLOR['red']}Критическая ошибка: {str(e)}{COLOR['reset']}")
        sys.exit(1)
