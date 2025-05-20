import hashlib
import base58
import time
import coincurve

# Конфигурация
TARGET_ADDRESS = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"
START_KEY = 0x1A12F1DA9D7000000
END_KEY = 0x1A12F1DA9DFFFFFFF
HEX_PATTERN = '1a12f1d'
BANNED_SUFFIXES = ['aaaa', 'ffff']
BIT_TRANSITIONS_RANGE = (7, 9)

def count_bit_transitions(key: int) -> int:
    """Быстрый подсчет битовых переходов"""
    xor = key ^ (key >> 1)
    return bin(xor).count('1')

def is_valid_key(key: int) -> bool:
    """Оптимизированная проверка ключа"""
    hex_key = f"{key:016x}"
    
    # Быстрые проверки в порядке возрастания сложности
    if HEX_PATTERN not in hex_key:
        return False
        
    if any(hex_key.endswith(s) for s in BANNED_SUFFIXES):
        return False
        
    transitions = count_bit_transitions(key)
    if not BIT_TRANSITIONS_RANGE[0] <= transitions <= BIT_TRANSITIONS_RANGE[1]:
        return False
        
    return True

def private_to_address(private_key_hex: str) -> str:
    """Преобразование приватного ключа в адрес без кэширования"""
    priv = bytes.fromhex(private_key_hex)
    pub = coincurve.PublicKey.from_valid_secret(priv).format(compressed=True)
    h160 = hashlib.new('ripemd160', hashlib.sha256(pub).digest()).digest()
    extended = b'\x00' + h160
    checksum = hashlib.sha256(hashlib.sha256(extended).digest()).digest()[:4]
    return base58.b58encode(extended + checksum).decode('utf-8')

def main():
    print(f"\n=== Bitcoin Puzzle Solver ===")
    print(f"Целевой адрес: {TARGET_ADDRESS}")
    print(f"Диапазон: {hex(START_KEY)} - {hex(END_KEY)}")
    print(f"Всего ключей: {(END_KEY-START_KEY+1):,}")
    print("==============================")
    
    start_time = time.time()
    last_log_time = time.time()
    keys_checked = 0
    valid_keys = 0
    
    for key in range(START_KEY, END_KEY + 1):
        keys_checked += 1
        
        if not is_valid_key(key):
            continue
            
        valid_keys += 1
        private_key = f"{key:064x}"
        address = private_to_address(private_key)
        
        if address == TARGET_ADDRESS:
            print(f"\n>>> КЛЮЧ НАЙДЕН! <<<")
            print(f"Приватный ключ: {private_key}")
            print(f"Hex: {hex(key)}")
            with open("found_key.txt", "w") as f:
                f.write(f"Адрес: {TARGET_ADDRESS}\n")
                f.write(f"Ключ: {private_key}\n")
                f.write(f"Hex: {hex(key)}\n")
            return
        
        # Логирование прогресса каждые 5 секунд
        if time.time() - last_log_time > 5:
            elapsed = time.time() - start_time
            speed = int(keys_checked / elapsed) if elapsed > 0 else 0
            print(f"\rПрогресс: {hex(key)} | "
                  f"Проверено: {keys_checked:,} | "
                  f"Валидных: {valid_keys:,} | "
                  f"Скорость: {speed:,} keys/s", end="", flush=True)
            last_log_time = time.time()
    
    print("\nПоиск завершен. Ключ не найден.")
    print(f"Всего проверено ключей: {keys_checked:,}")
    print(f"Валидных ключей: {valid_keys:,}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nПоиск остановлен пользователем.")
