# cython: language_level=3
# distutils: extra_compile_args = -O3 -march=native -fopenmp
# distutils: extra_link_args = -fopenmp

import cython
from libc.math cimport isfinite
from libc.stdint cimport uint64_t
import hashlib
import coincurve
import numpy as np
cimport numpy as np
from numba import njit
import os
import psutil
from math import isfinite

# Импорт конфигурации
from .config import CONFIG

@cython.boundscheck(False)
@cython.wraparound(False)
cdef inline bint is_valid_key(str key_hex):
    """Оптимизированная проверка ключа на Cython"""
    if len(key_hex) != CONFIG['min_key_length']:
        return False
    
    if not key_hex.startswith('0'*46) or key_hex[46] not in '4567':
        return False
    
    cdef str last_17 = key_hex[-17:]
    
    if '11111' in last_17 or 'aaaaa' in last_17 or '22222' in last_17 or 'bbbbb' in last_17:
        return False
    
    cdef int i
    for i in range(len(last_17) - CONFIG['max_repeats']):
        if len(set(last_17[i:i+CONFIG['max_repeats']+1])) == 1:
            return False
    
    if has_sequence(last_17, CONFIG['max_sequence']):
        return False
    
    return True

@njit
def has_sequence(s: str, max_seq: int) -> bool:
    """Проверка последовательностей с Numba"""
    cdef int i, delta
    if len(s) < 2:
        return False
    
    delta = ord(s[1]) - ord(s[0])
    if delta == 0:
        return False
        
    for i in range(1, len(s)-1):
        if ord(s[i+1]) - ord(s[i]) != delta:
            return False
    return len(s) >= max_seq

@cython.boundscheck(False)
@cython.wraparound(False)
def process_range(uint64_t start_key, uint64_t end_key, int thread_id):
    """Обработка диапазона ключей на Cython"""
    cdef uint64_t current = start_key
    cdef uint64_t checked = 0
    cdef str key_hex, h
    cdef bytes key_bytes, pub_key, pub_key_hash
    
    progress_file = os.path.join("progress_states", f"thread_{thread_id}.progress")
    
    try:
        os.makedirs("progress_states", exist_ok=True)
        with open(progress_file, 'w') as f:
            f.write(f"START {start_key} {end_key}\n")
        
        while current <= end_key:
            key_hex = f"{current:064x}"
            
            if is_valid_key(key_hex):
                key_bytes = bytes.fromhex(key_hex)
                pub_key = coincurve.PublicKey.from_secret(key_bytes).format(compressed=True)
                pub_key_hash = hashlib.sha256(pub_key).digest()
                h = hashlib.new('ripemd160', pub_key_hash).hexdigest()
                
                if h == CONFIG['target_hash']:
                    with open(progress_file, 'a') as f:
                        f.write(f"FOUND {key_hex}\n")
                    return
            
            checked += 1
            current += 1
            
            if checked % 100000 == 0:
                with open(progress_file, 'a') as f:
                    f.write(f"PROGRESS {current}\n")
    
    except Exception as e:
        with open(progress_file, 'a') as f:
            f.write(f"ERROR {str(e)}\n")
    finally:
        with open(progress_file, 'a') as f:
            f.write(f"END {checked}\n")
