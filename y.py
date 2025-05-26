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
START_RANGE = 0x349b84b643196c4ef1
END_RANGE = 0x349b84b6431a6c4ef1
NUM_THREADS = 12
AUTOSAVE_INTERVAL = 300
BACKUP_COUNT = 3

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

class ConsoleDisplay:
    def __init__(self, num_threads):
        self.num_threads = num_threads
        self.line_map = {
            'header': 0,
            'test': 4,
            'config': 8,
            'threads_header': 12,
            'threads_start': 13,
            'stats_start': 13 + num_threads + 1,
            'reasons_start': 13 + num_threads + 6,
            'progress_start': 13 + num_threads + 12
        }
        self.last_update = 0
        self.update_interval = 0.2
        
    def init_display(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        print("\033[H")  # Move cursor to home position
        
        # Header
        self.print_at('header', f"{COLOR['blue']}{COLOR['bold']}{'='*60}")
        self.print_at('header+1', f"{'ПОИСК КРИПТОГРАФИЧЕСКИХ КЛЮЧЕЙ':^60}")
        self.print_at('header+2', f"{'='*60}{COLOR['reset']}")
        
        # Test info
        self.print_at('test', f"{COLOR['bold']}Тест хеширования:{COLOR['reset']}")
        
        # Config
        self.print_at('config', f"{COLOR['bold']}Настройки поиска:{COLOR['reset']}")
        
        # Threads table header
        self.print_at('threads_header', f"{'Поток':<8}{'Статус':<15}{'Обработано':<12}{'Интересных':<12}{'Пропущено':<12}{'Блоков':<12}")
        
        # Initialize empty thread lines
        for i in range(self.num_threads):
            self.print_at(f'threads_start+{i}', "")
        
        # Stats
        self.print_at('stats_start', f"{COLOR['bold']}Общая статистика:{COLOR['reset']}")
        
        # Skip reasons
        self.print_at('reasons_start', f"{COLOR['bold']}Причины пропуска ключей:{COLOR['reset']}")
        
        # Progress bar
        self.print_at('progress_start', f"{COLOR['bold']}Прогресс:{COLOR['reset']}")
        
    def print_at(self, position, text):
        if '+' in position:
            base, offset = position.split('+')
            line = self.line_map[base] + int(offset)
        else:
            line = self.line_map[position]
        print(f"\033[{line};0H\033[K{text}", end="")
        
    def update_test_info(self, passed):
        status = f"{COLOR['green']}✅ ПРОЙДЕН" if passed else f"{COLOR['red']}❌ НЕ ПРОЙДЕН"
        self.print_at('test', f"{COLOR['bold']}Тест хеширования:{COLOR['reset']} {status}")
        self.print_at('test+1', f"Тестовый ключ: {TEST_KEY}")
        self.print_at('test+2', f"Ожидаемый хеш: {TEST_HASH}")
        
    def update_config(self):
        self.print_at('config', f"{COLOR['bold']}Настройки поиска:{COLOR['reset']}")
        self.print_at('config+1', f"Диапазон: 0x{START_RANGE:016x} - 0x{END_RANGE:016x}")
        self.print_at('config+2', f"Потоков: {NUM_THREADS}")
        
    def update_thread(self, thread_id, key_hex, current_hash, processed, interesting):
        if time.time() - self.last_update < self.update_interval:
            return
            
        last_18 = key_hex[-18:] if len(key_hex) >= 18 else key_hex
        key_display = f"0x{last_18}"
        hash_display = f"{current_hash[:8]}...{current_hash[-8:]}"
        
        self.print_at(f'threads_start+{thread_id}', 
            f"{thread_id:<8}{COLOR['cyan']}работает{COLOR['reset']:<15}"
            f"{processed:<12}{interesting:<12}"
            f"{'-':<12}{'-':<12}"
            f"Ключ: {key_display} Хеш: {hash_display}")
        
        self.last_update = time.time()
        
    def update_stats(self, futures, start_time):
        completed = 0
        found = False
        total_stats = {
            'processed': 0,
            'skipped_blocks': 0,
            'total_skipped_keys': 0,
            'interesting_keys': 0,
            'reasons': {
                'repeating_chars': 0,
                'sequential': 0,
                'symmetric': 0,
                'unique_chars': 0
            }
        }
        
        for future in futures:
            if future.done():
                result = future.result()
                if result.get('status') == 'found':  # Исправлено: добавлена проверка .get()
                    found = True
                completed += 1
                
                for stat in ['processed', 'skipped_blocks', 'total_skipped_keys', 'interesting_keys']:
                    total_stats[stat] += result['stats'][stat]
                
                for reason in total_stats['reasons']:
                    total_stats['reasons'][reason] += result['stats']['reasons'].get(reason, 0)
        
        # Update thread statuses
        for i, future in enumerate(futures):
            if future.done():
                result = future.result()
                status = f"{COLOR['green']}завершен{COLOR['reset']}"
                blocks = f"{len(result['stats']['blocks'])} ({result['stats']['skipped_blocks']})"
                
                self.print_at(f'threads_start+{i}',
                    f"{i:<8}{status:<15}"
                    f"{result['stats']['processed']:<12}"
                    f"{result['stats']['interesting_keys']:<12}"
                    f"{result['stats']['total_skipped_keys']:<12}"
                    f"{blocks:<12}")
        
        # Update stats
        self.print_at('stats_start+1', f"Обработано ключей: {total_stats['processed']}")
        self.print_at('stats_start+2', f"Потенциально интересных ключей: {total_stats['interesting_keys']}")
        self.print_at('stats_start+3', f"Пропущено ключей: {total_stats['total_skipped_keys']}")
        self.print_at('stats_start+4', f"Всего блоков: {sum(len(f.result()['stats']['blocks']) for f in futures if f.done())} (пропущено: {total_stats['skipped_blocks']})")
        
        # Update skip reasons
        for i, (reason, count) in enumerate(total_stats['reasons'].items()):
            self.print_at(f'reasons_start+{i+1}', f"- {reason}: {count}")
        
        # Update progress
        if not found:
            progress = sum(f.result()['stats']['current']-START_RANGE for f in futures if f.done()) / (END_RANGE - START_RANGE)
            bar_length = 50
            filled = int(bar_length * progress)
            bar = f"{COLOR['green']}{'#'*filled}{COLOR['reset']}{'-'*(bar_length-filled)}"
            self.print_at('progress_start+1', f"[{bar}] {progress*100:.21f}%")
        
        return found

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
    last_17 = key_hex[-17:]
    
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


def worker(thread_id, start, end, initial_state=None):
    state = {
        'processed': 0,
        'skipped_blocks': 0,
        'total_skipped_keys': 0,
        'current': start,
        'last_key': None,
        'start_time': time.time(),
        'last_save': time.time(),
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
            h = hashlib.new('ripemd160', hashlib.sha256(pub_key).digest()).hexdigest()
            
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
                    'thread_id': thread_id,
                    'stats': state
                }
                
            state['processed'] += 1
            state['interesting_keys'] += 1
            
            if time.time() - state['last_save'] > AUTOSAVE_INTERVAL:
                state['current'] = current
                with open(f'progress_thread_{thread_id}.pkl', 'wb') as f:
                    pickle.dump(state, f)
                state['last_save'] = time.time()
                
            return state  # Return partial results for display
                
        except Exception as e:
            print(f"{COLOR['red']}Ошибка в потоке {thread_id}: {str(e)}{COLOR['reset']}")
        
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

def get_skip_reason(key_hex):
    last_17 = key_hex[-17:]
    
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

def main():
    display = ConsoleDisplay(NUM_THREADS)
    display.init_display()
    
    # Run and display test
    test_passed = run_hash_test()
    display.update_test_info(test_passed)
    display.update_config()
    
    if not test_passed:
        print(f"\n{COLOR['red']}Тест хеширования не пройден. Проверьте настройки.{COLOR['reset']}")
        return
    
    chunk_size = (END_RANGE - START_RANGE) // NUM_THREADS
    ranges = []
    for i in range(NUM_THREADS):
        start = START_RANGE + i * chunk_size
        end = start + chunk_size - 1 if i < NUM_THREADS - 1 else END_RANGE
        ranges.append((i, start, end))
    
    start_time = time.time()
    found_key = None
    
    with ProcessPoolExecutor(max_workers=NUM_THREADS) as executor:
        futures = [executor.submit(worker, *args) for args in ranges]
        
        try:
            while True:
                time.sleep(0.1)
                
                # Update display with partial results
                for i, future in enumerate(futures):
                    try:
                        if not future.done() and future._result:
                            result = future._result
                            key_hex = result['last_key']
                            pub_key = coincurve.PublicKey.from_secret(bytes.fromhex(key_hex)).format(compressed=True)
                            h = hashlib.new('ripemd160', hashlib.sha256(pub_key).digest()).hexdigest()
                            display.update_thread(
                                i, 
                                key_hex, 
                                h,
                                result['processed'],
                                result['interesting_keys']
                            )
                    except:
                        pass
                
                # Update stats
                found = display.update_stats(futures, start_time)
                
                if found:
                    for future in futures:
                        if future.done() and future.result().get('status') == 'found':  # Исправлено: добавлена проверка .get()
                            found_key = future.result()['key']
                            break
                    break
                    
                if all(future.done() for future in futures):
                    break
                    
        except KeyboardInterrupt:
            display.print_at('progress_start+3', f"{COLOR['yellow']}Остановлено пользователем{COLOR['reset']}")
    
    if found_key:
        display.print_at('progress_start+3', f"{COLOR['green']}{'='*60}")
        display.print_at('progress_start+4', f"{'КЛЮЧ НАЙДЕН!':^60}")
        display.print_at('progress_start+5', f"{'='*60}{COLOR['reset']}")
        display.print_at('progress_start+6', f"{COLOR['bold']}Приватный ключ:{COLOR['reset']} {COLOR['green']}{found_key}{COLOR['reset']}")
        
        key_bytes = bytes.fromhex(found_key)
        pub_key = coincurve.PublicKey.from_secret(key_bytes).format(compressed=True)
        h = hashlib.new('ripemd160', hashlib.sha256(pub_key).digest()).hexdigest()
        display.print_at('progress_start+7', f"{COLOR['bold']}Найденный хеш:{COLOR['reset']} {h}")
        display.print_at('progress_start+8', f"{COLOR['bold']}Ожидаемый хеш:{COLOR['reset']} {TARGET_HASH}")
        display.print_at('progress_start+9', f"{COLOR['green']}{'='*60}{COLOR['reset']}")
        
        # Cleanup progress files
        for i in range(NUM_THREADS):
            try:
                os.remove(f'progress_thread_{i}.pkl')
            except:
                pass

    # Move cursor to end of output
    print(f"\033[{display.line_map['progress_start']+20};0H")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"{COLOR['red']}Критическая ошибка: {str(e)}{COLOR['reset']}")
        sys.exit(1)
