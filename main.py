# -*- coding: utf-8 -*-
import hashlib
import coincurve
from concurrent.futures import ProcessPoolExecutor
import time
import sys
import re
import pickle

# Глобальная конфигурация
TARGET_HASH = "f6f5431d25bbf7b12e8add9af5e3475c44a0a5b8"
TEST_KEY = "0000000000000000000000000000000000000000000000000000000000000001"
TEST_HASH = "751e76e8199196d454941c45d1b3a323f1433bd6"
PROGRESS_STEP = 100  # Шаг обновления прогресса
SKIP_UPDATE_INTERVAL = 5000000  # Интервал обновления статистики пропусков
MIN_UPDATE_INTERVAL = 0.1  # Минимальный интервал между обновлениями (сек)

# Фиксированные диапазоны для потоков
THREAD_CONFIG = {
    0: {'start': 0x400000000000000000, 'end': 0x480000000000000000, 'current': None, 'processed': 0, 'skipped': 0},
    1: {'start': 0x480000000000000000, 'end': 0x500000000000000000, 'current': None, 'processed': 0, 'skipped': 0},
    2: {'start': 0x500000000000000000, 'end': 0x580000000000000000, 'current': None, 'processed': 0, 'skipped': 0},
    3: {'start': 0x580000000000000000, 'end': 0x600000000000000000, 'current': None, 'processed': 0, 'skipped': 0},
    4: {'start': 0x600000000000000000, 'end': 0x680000000000000000, 'current': None, 'processed': 0, 'skipped': 0},
    5: {'start': 0x680000000000000000, 'end': 0x700000000000000000, 'current': None, 'processed': 0, 'skipped': 0},
    6: {'start': 0x700000000000000000, 'end': 0x780000000000000000, 'current': None, 'processed': 0, 'skipped': 0},
    7: {'start': 0x780000000000000000, 'end': 0x800000000000000000, 'current': None, 'processed': 0, 'skipped': 0}
}

# ANSI escape codes
CURSOR_UP = "\033[F"
ERASE_LINE = "\033[K"

def should_skip_key(key_hex):
    """Фильтрация ключей по паттернам в последних 17 символах"""
    last_17 = key_hex[-17:]
    
    # Проверка всех условий фильтрации
    patterns = [
        r'^[0-9]{17}$',        # Все цифры
        r'^[a-f]{17}$',        # Все буквы a-f
        r'(.)\1{3}',           # 4+ одинаковых символа подряд
        r'([0-9]{5,}|[a-f]{5,})' # 5+ цифр или букв подряд
    ]
    
    return any(re.search(pattern, last_17) for pattern in patterns)

def run_hash_test():
    """Полный тест хеширования с подробным выводом"""
    print("\n" + "="*60)
    print("🔧 ПОЛНЫЙ ТЕСТ ХЕШИРОВАНИЯ")
    print("="*60)
    
    print(f"Тестовый ключ: {TEST_KEY}")
    
    try:
        # Шаг 1: Получение публичного ключа
        key_bytes = bytes.fromhex(TEST_KEY)
        pub_key = coincurve.PublicKey.from_secret(key_bytes).format(compressed=True)
        print(f"\n1. Публичный ключ (сжатый): {pub_key.hex()}")
        
        # Шаг 2: SHA256 хеш
        sha256_hash = hashlib.sha256(pub_key).digest()
        print(f"2. SHA256: {sha256_hash.hex()}")
        
        # Шаг 3: RIPEMD160 хеш
        ripemd160 = hashlib.new('ripemd160', sha256_hash).hexdigest()
        print(f"3. RIPEMD160: {ripemd160}")
        
        # Проверка результата
        print(f"\nОжидаемый RIPEMD160: {TEST_HASH}")
        test_passed = ripemd160 == TEST_HASH
        print(f"Результат: {'✅ ТЕСТ ПРОЙДЕН' if test_passed else '❌ ТЕСТ НЕ ПРОЙДЕН'}")
        
        return test_passed
    except Exception as e:
        print(f"\n❌ ОШИБКА В ТЕСТЕ: {str(e)}")
        return False

def run_filter_tests():
    """Полный тест фильтрации ключей"""
    print("\n" + "="*60)
    print("🔍 ПОЛНЫЙ ТЕСТ ФИЛЬТРА КЛЮЧЕЙ")
    print("="*60)
    
    test_cases = [
        # Все цифры (должен пропустить)
        ("0000000000000000000000000000000000000000000000000000000000000000", True, "Все цифры"),
        # Все буквы a-f (должен пропустить)
        ("abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd", True, "Все буквы a-f"),
        # 4 одинаковых символа подряд (должен пропустить)
        ("aaaa1234567890abc1234567890abc1234567890abc1234567890abc123456", True, "4+ одинаковых символа"),
        # 5+ цифр подряд (должен пропустить)
        ("1234555556789012345678901234567890123456789012345678901234567890", True, "5+ цифр подряд"),
        # 5+ букв подряд (должен пропустить)
        ("abcddeeeef1234567890abc1234567890abc1234567890abc1234567890abcd", True, "5+ букв подряд"),
        # Нормальный ключ (не должен пропускать)
        ("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a", False, "Нормальный ключ"),
        # Ключ из примера (должен пропустить)
        ("0000000000000000000000000000000000000000000004c5ce114686a1336e07", True, "Пример 1"),
        # Ключ из примера (не должен пропускать)
        ("00000000000000000000000000000000000000000000000730fc235c1942c1ae", False, "Пример 2")
    ]
    
    print("Тестовые случаи:")
    print("-"*60)
    all_passed = True
    
    for key, should_skip, description in test_cases:
        result = should_skip_key(key)
        status = "✅" if result == should_skip else "❌"
        if status == "❌":
            all_passed = False
        
        print(f"{status} {description}:")
        print(f"Ключ: ...{key[-17:]}")
        print(f"Ожидалось: {'Пропустить' if should_skip else 'Принять'}")
        print(f"Фактически: {'Пропущен' if result else 'Принят'}")
        print("-"*60)
    
    print(f"\nИтог теста фильтрации: {'✅ ВСЕ ТЕСТЫ ПРОЙДЕНЫ' if all_passed else '❌ ЕСТЬ ОШИБКИ'}")
    return all_passed

class ProgressDisplay:
    """Класс для отображения прогресса с минимальными обновлениями"""
    def __init__(self, num_threads):
        self.num_threads = num_threads
        self.last_update = time.time()
        self.init_display()
    
    def init_display(self):
        """Инициализация дисплея с заголовками"""
        print("\n" + "="*60)
        print(f"⚡ ПОИСК КЛЮЧЕЙ | Целевой хеш: {TARGET_HASH}")
        print("="*60 + "\n")
        print(ERASE_LINE + "Всего: Обработано 0 | Пропущено 0 (0.0%)")
        for tid in range(self.num_threads):
            print(ERASE_LINE + f"Поток {tid}: 0 keys (0.0/s) | 0x...")
        sys.stdout.flush()
    
    def update(self, thread_id, processed, current_key, speed, force=False):
        """Обновление статистики с контролем частоты"""
        now = time.time()
        if not force and now - self.last_update < MIN_UPDATE_INTERVAL:
            return
            
        total_processed = sum(t['processed'] for t in THREAD_CONFIG.values())
        total_skipped = sum(t['skipped'] for t in THREAD_CONFIG.values())
        total = total_processed + total_skipped
        skipped_percent = total_skipped / total * 100 if total > 0 else 0
        
        # Перемещение курсора и обновление
        print(CURSOR_UP * (self.num_threads + 2), end="")
        print(ERASE_LINE + f"Всего: Обработано {total_processed:,} | Пропущено {total_skipped:,} ({skipped_percent:.1f}%)")
        
        short_key = f"0x...{current_key[-18:]}" if current_key else "0x..."
        print(ERASE_LINE + f"Поток {thread_id}: {processed:,} keys ({speed:.1f}/s) | {short_key}")
        
        # Возврат курсора на место
        print(CURSOR_UP * (self.num_threads - thread_id), end="")
        sys.stdout.flush()
        self.last_update = now

def process_range(thread_id, progress):
    """Обработка диапазона ключей"""
    config = THREAD_CONFIG[thread_id]
    current = config['current'] if config['current'] is not None else config['start']
    end = config['end']
    keys_processed = 0
    keys_skipped = 0
    last_report = time.time()
    
    # Первоначальный отчет
    progress.update(thread_id, 0, f"{current:064x}", 0, force=True)
    
    while current <= end:
        key_hex = f"{current:064x}"
        
        if not should_skip_key(key_hex):
            try:
                # Генерация публичного ключа и хеша
                pub_key = coincurve.PublicKey.from_secret(bytes.fromhex(key_hex)).format(compressed=True)
                h = hashlib.new('ripemd160', hashlib.sha256(pub_key).digest()).hexdigest()
                
                if h == TARGET_HASH:
                    print(f"\n🎉 КЛЮЧ НАЙДЕН в потоке {thread_id}: 0x{key_hex}")
                    return key_hex
                
                keys_processed += 1
                config['processed'] += 1
                
                # Отчет о прогрессе
                if keys_processed % PROGRESS_STEP == 0:
                    speed = PROGRESS_STEP / (time.time() - last_report)
                    progress.update(thread_id, keys_processed, key_hex, speed)
                    last_report = time.time()
                    config['current'] = current
                    
            except Exception as e:
                print(f"\n⚠ Ошибка в потоке {thread_id}: {str(e)}")
        else:
            keys_skipped += 1
            config['skipped'] += 1
            
            # Редкий отчет о пропущенных ключах
            if keys_skipped % SKIP_UPDATE_INTERVAL == 0:
                progress.update(thread_id, keys_processed, key_hex, 0)
        
        current += 1
    
    config['current'] = None
    return None

def save_state(filename='progress.pkl'):
    """Сохранение состояния поиска"""
    with open(filename, 'wb') as f:
        pickle.dump(THREAD_CONFIG, f)
    print(f"\n✔ Состояние сохранено в {filename}")

def load_state(filename='progress.pkl'):
    """Загрузка состояния поиска"""
    try:
        with open(filename, 'rb') as f:
            loaded = pickle.load(f)
            for k in THREAD_CONFIG:
                if k in loaded:
                    THREAD_CONFIG[k].update(loaded[k])
        print("✔ Состояние загружено")
        return True
    except FileNotFoundError:
        print("ℹ Файл состояния не найден, начинаем с начала")
        return False
    except Exception as e:
        print(f"⚠ Ошибка загрузки состояния: {str(e)}")
        return False

def main():
    """Основная функция выполнения"""
    print("🔍 ЗАПУСК ТЕСТОВ...")
    
    # Запуск всех тестов
    hash_test_passed = run_hash_test()
    filter_test_passed = run_filter_tests()
    
    if not all([hash_test_passed, filter_test_passed]):
        print("\n❌ ТЕСТЫ НЕ ПРОЙДЕНЫ. ВЫПОЛНЕНИЕ ОСТАНОВЛЕНО")
        return
    
    # Загрузка состояния
    print("\n⏳ ЗАГРУЗКА СОСТОЯНИЯ...")
    load_state()
    
    # Запуск поиска
    print("\n⚡ ЗАПУСК ПОИСКА...")
    print(f"Целевой хеш: {TARGET_HASH}")
    print(f"Количество потоков: {len(THREAD_CONFIG)}")
    print(f"Диапазон: 0x{THREAD_CONFIG[0]['start']:016x} - 0x{THREAD_CONFIG[7]['end']:016x}")
    
    start_time = time.time()
    progress = ProgressDisplay(len(THREAD_CONFIG))
    
    try:
        with ProcessPoolExecutor(max_workers=len(THREAD_CONFIG)) as executor:
            futures = {executor.submit(process_range, tid, progress): tid for tid in THREAD_CONFIG}
            
            for future in futures:
                if result := future.result():
                    print(f"\n⌛ ВРЕМЯ ВЫПОЛНЕНИЯ: {time.time() - start_time:.1f} сек")
                    save_state()
                    return
                    
    except KeyboardInterrupt:
        print("\n⏹ ПОИСК ОСТАНОВЛЕН ПОЛЬЗОВАТЕЛЕМ")
    except Exception as e:
        print(f"\n❌ КРИТИЧЕСКАЯ ОШИБКА: {str(e)}")
    finally:
        save_state()
        print("\nТЕКУЩИЕ ПОЗИЦИИ ПОТОКОВ:")
        for tid in sorted(THREAD_CONFIG):
            curr = THREAD_CONFIG[tid]['current']
            print(f"Поток {tid}: {f'0x{curr:016x}' if curr is not None else 'завершен'}")

if __name__ == "__main__":
    main()
