# fast_utils.pyx
import cython
from libc.stdint cimport uint64_t

@cython.boundscheck(False)
@cython.wraparound(False)
def is_valid_key_cython(str key_hex, int max_repeats, int max_sequence, int max_similar):
    cdef int length = len(key_hex)
    if length != 64:
        return False
    
    if not key_hex.startswith('0'*46):
        return False
    
    cdef char first_char = key_hex[46]
    if first_char not in {'4','5','6','7'}:
        return False
    
    cdef str last_17 = key_hex[-17:]
    cdef int i, j, delta, repeat_count = 1
    cdef char c
    
    # Проверка повторений
    for i in range(1, len(last_17)):
        if last_17[i] == last_17[i-1]:
            repeat_count += 1
            if repeat_count > max_repeats:
                return False
        else:
            repeat_count = 1
    
    # Проверка последовательностей
    for i in range(len(last_17) - max_sequence):
        delta = ord(last_17[i+1]) - ord(last_17[i])
        if delta == 0:
            continue
            
        for j in range(i+1, i+max_sequence):
            if ord(last_17[j+1]) - ord(last_17[j]) != delta:
                break
        else:
            return False
    
    # Проверка частоты символов
    cdef dict char_counts = {}
    for c in last_17:
        char_counts[c] = char_counts.get(c, 0) + 1
        if char_counts[c] > max_similar:
            return False
    
    return True
