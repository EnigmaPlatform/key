#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import multiprocessing
import time
import random
import hashlib
import secp256k1
import sys
import numpy as np
from numba import njit
from threading import Lock
from ctypes import c_uint64
from multiprocessing.sharedctypes import Value
import os

# ========== КОНФИГУРАЦИЯ ==========
TARGET_HASH = b"\xf6\xf5\x43\x1d\x25\xbb\xf7\xb1\x2e\x8a\xdd\x9a\xf5\xe3\x47\x5c\x44\xa0\xa5\xb8"
TARGET_PREFIX = TARGET_HASH[:3]
START_RANGE = 0x400000000000000000
END_RANGE = 0x7fffffffffffffffff
NUM_THREADS = min(multiprocessing.cpu_count(), 8)
KEYS_TO_CHECK = 150_000_000
BATCH_SIZE = 100_000
UPDATE_INTERVAL = 0.1  # сек

# ========== ОПТИМИЗАЦИИ СИСТЕМЫ ==========
if sys.platform == 'linux':
    os.nice(-20)  # Максимальный приоритет процесса
    try:
        import ctypes
        libc = ctypes.CDLL('libc.so.6')
        libc.malloc_trim(0)  # Освобождаем память для Linux
    except:
        pass

# ========== ПРЕДВАРИТЕЛЬНАЯ КОМПИЛЯЦИЯ ==========
TARGET_PREFIX_NP = np.frombuffer(TARGET_PREFIX, dtype=np.uint8)
TARGET_HASH_NP = np.frombuffer(TARGET_HASH, dtype=np.uint8)

@njit(nogil=True, cache=True, fastmath=True, boundscheck=False)
def numba_check_match(digest):
    """Оптимизированная проверка хешей с использованием SIMD-операций"""
    # Быстрая проверка первых 3 байт
    if (digest[0] ^ TARGET_PREFIX_NP[0]) | \
       (digest[1] ^ TARGET_PREFIX_NP[1]) | \
       (digest[2] ^ TARGET_PREFIX_NP[2]):
        return False
    
    # Векторизованная проверка остальных байт
    for i in range(3, len(TARGET_HASH_NP)):
        if digest[i] != TARGET_HASH_NP[i]:
            return False
    return True

# ========== КЛАССЫ ДЛЯ УПРАВЛЕНИЯ ==========
class SpeedTracker:
    __slots__ = ['total_keys', 'counter', 'last_time', 'speed', 'lock', 'samples', 'idx']
    
    def __init__(self, total_keys):
        self.total_keys = total_keys
        self.counter = Value(c_uint64, 0)
        self.last_time = Value('d', time.time())
        self.speed = Value('d', 0.0)
        self.lock = Lock()
        self.samples = multiprocessing.Array('d', [0.0]*5)
        self.idx = 0

    def update(self, count):
        with self.lock:
            if self.counter.value >= self.total_keys:
                return
                
            self.counter.value += count
            now = time.time()
            time_diff = now - self.last_time.value
            
            if time_diff > 0:
                current_speed = count / time_diff
                self.samples[self.idx % 5] = current_speed
                self.idx += 1
                self.speed.value = sum(self.samples) / min(5, self.idx)
                self.last_time.value = now

    def get_stats(self):
        with self.lock:
            return self.counter.value, self.speed.value

    def should_stop(self):
        with self.lock:
            return self.counter.value >= self.total_keys

class WorkBalancer:
    __slots__ = ['position', 'end', 'lock']
    
    def __init__(self, start, end):
        self.position = Value(c_uint64, start)
        self.end = end
        self.lock = Lock()

    def get_next_batch(self):
        with self.lock:
            current = self.position.value
            if current >= self.end:
                return None, 0
            
            batch_size = min(BATCH_SIZE, self.end - current)
            self.position.value += batch_size
            return current, batch_size

# ========== ОСНОВНЫЕ ФУНКЦИИ ==========
def double_hash(data):
    """Оптимизированное хеширование с предварительным выделением памяти"""
    sha = hashlib.sha256(data).digest()
    rmd = hashlib.new('ripemd160', sha).digest()
    return rmd

def worker(balancer, progress, found_flag, found_key):
    """Рабочая функция с оптимизированным циклом"""
    ctx = secp256k1.lib.secp256k1_context_create(
        secp256k1.lib.SECP256K1_CONTEXT_SIGN | 
        secp256k1.lib.SECP256K1_CONTEXT_VERIFY)
    
    # Предварительное выделение памяти
    digest_buffer = np.empty(20, dtype=np.uint8)
    
    try:
        while not found_flag.value and not progress.should_stop():
            batch = balancer.get_next_batch()
            if not batch or not batch[1]:
                break
                
            current, batch_size = batch
            count = 0
            
            for i in range(current, current + batch_size):
                if found_flag.value or progress.should_stop():
                    break
                    
                # Исправленный код: прямое преобразование в bytes
                private_key = i.to_bytes(32, 'big')
                private_key_c = secp256k1.ffi.new("unsigned char [32]", private_key)
                
                pubkey = secp256k1.ffi.new('secp256k1_pubkey *')
                if not secp256k1.lib.secp256k1_ec_pubkey_create(ctx, pubkey, private_key_c):
                    continue
                
                out = secp256k1.ffi.new('unsigned char [33]')
                out_len = secp256k1.ffi.new('size_t *', 33)
                
                secp256k1.lib.secp256k1_ec_pubkey_serialize(
                    ctx, out, out_len, pubkey, secp256k1.lib.SECP256K1_EC_COMPRESSED)
                
                pubkey_bytes = bytes(secp256k1.ffi.buffer(out, 33))
                
                if pubkey_bytes:
                    ripemd160 = double_hash(pubkey_bytes)
                    digest_buffer[:] = np.frombuffer(ripemd160, dtype=np.uint8)
                    
                    if numba_check_match(digest_buffer):
                        with found_key.get_lock():
                            found_key.value = i
                        found_flag.value = True
                        break
                
                count += 1
            
            if count > 0:
                progress.update(count)
    finally:
        secp256k1.lib.secp256k1_context_destroy(ctx)

def display_progress(progress, found_flag):
    """Отображение прогресса с оптимизированными выводами"""
    start_time = time.time()
    last_speeds = []
    terminal_width = 80
    
    # Инициализация пустой строки
    sys.stdout.write("\r" + " " * terminal_width)
    sys.stdout.flush()
    
    while not found_flag.value and not progress.should_stop():
        completed, speed = progress.get_stats()
        elapsed = max(0.1, time.time() - start_time)
        percent = min(100.0, completed / KEYS_TO_CHECK * 100)
        
        # Экспоненциальное скользящее среднее для скорости
        if not last_speeds:
            last_speeds.append(speed)
        else:
            last_speeds.append(0.8 * last_speeds[-1] + 0.2 * speed)
        
        if len(last_speeds) > 5:
            last_speeds.pop(0)
        avg_speed = last_speeds[-1]
        
        # Форматирование строки прогресса
        progress_text = (
            f"Прогресс: {percent:.2f}% | "
            f"Время: {elapsed:.1f}s | "
            f"Скорость: {avg_speed/1000:.1f}K keys/s | "
            f"Ключей: {completed:,}"
        )
        
        # Обновление строки
        sys.stdout.write("\r" + progress_text.ljust(terminal_width))
        sys.stdout.flush()
        
        time.sleep(UPDATE_INTERVAL)
    
    # Очистка строки
    sys.stdout.write("\r" + " " * terminal_width + "\r")
    sys.stdout.flush()

def test_hashing():
    """Оптимизированное тестирование работы хеширования"""
    print("\n🔍 Тестирование хеширования...")
    test_key = 1
    expected_hash = "751e76e8199196d454941c45d1b3a323f1433bd6"
    
    ctx = secp256k1.lib.secp256k1_context_create(
        secp256k1.lib.SECP256K1_CONTEXT_SIGN | 
        secp256k1.lib.SECP256K1_CONTEXT_VERIFY)
    
    try:
        private_key = test_key.to_bytes(32, 'big')
        private_key_c = secp256k1.ffi.new("unsigned char [32]", private_key)
        
        pubkey = secp256k1.ffi.new('secp256k1_pubkey *')
        if not secp256k1.lib.secp256k1_ec_pubkey_create(ctx, pubkey, private_key_c):
            print("❌ Ошибка генерации публичного ключа")
            return False
        
        out = secp256k1.ffi.new('unsigned char [33]')
        out_len = secp256k1.ffi.new('size_t *', 33)
        
        secp256k1.lib.secp256k1_ec_pubkey_serialize(
            ctx, out, out_len, pubkey, secp256k1.lib.SECP256K1_EC_COMPRESSED)
        
        pubkey_bytes = bytes(secp256k1.ffi.buffer(out, 33))
        actual_hash = double_hash(pubkey_bytes).hex()
        
        if actual_hash == expected_hash:
            print("✅ Хеширование работает корректно")
            return True
        else:
            print(f"❌ Ошибка: ожидалось {expected_hash}, получено {actual_hash}")
            return False
    finally:
        secp256k1.lib.secp256k1_context_destroy(ctx)

def main():
    # Инициализация
    print("\n" + "="*50)
    print(f"🔍 Поиск ключа с префиксом: {TARGET_PREFIX.hex()}")
    print(f"💻 Используется ядер: {NUM_THREADS}")
    print(f"🧮 Всего ключей для проверки: {KEYS_TO_CHECK:,}")
    print("="*50)
    
    # Компиляция Numba
    print("\n⚙ Компиляция Numba-функций...", end=' ', flush=True)
    _ = numba_check_match(np.zeros(20, dtype=np.uint8))
    print("Готово!")
    
    # Тестирование
    if not test_hashing():
        sys.exit(1)
    
    # Инициализация поиска
    random_start = random.randint(START_RANGE, END_RANGE - KEYS_TO_CHECK)
    print(f"\n🎲 Случайная начальная точка: 0x{random_start:064x}")
    
    progress = SpeedTracker(KEYS_TO_CHECK)
    found_flag = Value('b', False)
    found_key = Value(c_uint64, 0)
    balancer = WorkBalancer(random_start, random_start + KEYS_TO_CHECK)

    # Запуск процессов
    processes = []
    for _ in range(NUM_THREADS):
        p = multiprocessing.Process(
            target=worker,
            args=(balancer, progress, found_flag, found_key),
            daemon=True
        )
        processes.append(p)
        p.start()
    
    # Запуск отображения прогресса
    display_process = multiprocessing.Process(
        target=display_progress,
        args=(progress, found_flag),
        daemon=True
    )
    display_process.start()

    # Ожидание завершения
    try:
        while not found_flag.value and not progress.should_stop():
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n🛑 Остановлено пользователем")
        found_flag.value = True
    
    # Завершение процессов
    for p in processes:
        p.terminate()
    display_process.terminate()
    
    # Вывод результатов
    completed = progress.counter.value
    elapsed = time.time() - start_time
    
    print("\n" + "="*50)
    print("🏁 Результаты поиска:")
    if found_flag.value:
        print(f"🔑 Найден ключ: 0x{found_key.value:064x}")
    else:
        print("🔍 Ключ не найден")
    print(f"⏱ Затраченное время: {elapsed:.1f} сек")
    print(f"⚡ Средняя скорость: {completed/elapsed/1000:.1f}K keys/s")
    print(f"✅ Проверено ключей: {completed:,}")
    print("="*50)

if __name__ == "__main__":
    start_time = time.time()
    main()
