import cython

@cython.boundscheck(False)
@cython.wraparound(False)
def is_valid_key(key_hex: str) -> cython.bint:
    # Игнорируем ведущие нули (первые 46 символов)
    significant_part = key_hex[46:]
    
    # 1. Проверка на ключи только из цифр или только из букв
    if significant_part.isdigit() or significant_part.isalpha():
        return False
    
    # 2. Проверка на более 4 повторяющихся символов подряд
    cdef int i, count = 1
    cdef char current = significant_part[0]
    for i in range(1, len(significant_part)):
        if significant_part[i] == current:
            count += 1
            if count > 4:
                return False
        else:
            current = significant_part[i]
            count = 1
    
    return True
