import hashlib
import random
import base58
import ecdsa
import time
import logging
import json
import os
from tqdm import tqdm

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    END = '\033[0m'

# Конфигурация
CHECKPOINT_FILE = "checked_ranges.json"
CHUNK_SIZE = 10_000_000  # 10 миллионов ключей после случайной точки
MAIN_START = 0x400000000000000000
MAIN_END = 0x7fffffffffffffffff

# Настройка логгирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('btc_finder.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def load_checked_ranges():
    """Загружает проверенные диапазоны из файла"""
    if os.path.exists(CHECKPOINT_FILE):
        try:
            with open(CHECKPOINT_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Ошибка загрузки файла прогресса: {e}")
            return []
    return []

def save_checked_ranges(ranges):
    """Сохраняет проверенные диапазоны в файл"""
    try:
        with open(CHECKPOINT_FILE, 'w') as f:
            json.dump(ranges, f, indent=2)
    except Exception as e:
        logger.error(f"Ошибка сохранения прогресса: {e}")

def is_key_checked(key_int, checked_ranges):
    """Проверяет, был ли ключ или его диапазон уже проверен"""
    for r in checked_ranges:
        if r['start'] <= key_int <= r['end']:
            return True
    return False

def generate_address(private_key_hex):
    """Генерирует Bitcoin-адрес из приватного ключа"""
    try:
        # Валидация ключа
        if len(private_key_hex) != 64:
            raise ValueError("Некорректная длина ключа")
        
        # Конвертация в ECDSA ключ
        private_key_bytes = bytes.fromhex(private_key_hex)
        sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        
        # Compressed public key
        x = vk.pubkey.point.x()
        y = vk.pubkey.point.y()
        prefix = '02' if y % 2 == 0 else '03'
        public_key_compressed = bytes.fromhex(prefix + "%064x" % x)
        
        # Хеширование
        sha256 = hashlib.sha256(public_key_compressed).digest()
        ripemd160 = hashlib.new('ripemd160', sha256).digest()
        
        # Формирование адреса
        extended_hash = b'\x00' + ripemd160
        checksum = hashlib.sha256(hashlib.sha256(extended).digest())[:4]
        address = base58.b58encode(extended_hash + checksum).decode('utf-8')
        
        return address
    except Exception as e:
        logger.error(f"{Colors.RED}Ошибка генерации адреса: {e}{Colors.END}")
        return None

def log_success(private_key_hex, address):
    """Логирует найденный ключ"""
    message = f"""
    {Colors.GREEN}
    ╔═══════════════════════════════════════════════════╗
    ║                КЛЮЧ НАЙДЕН!                       ║
    ╠═══════════════════════════════════════════════════╣
    ║ Приватный ключ: {private_key_hex[:32]}...{private_key_hex[-32:]} ║
    ║ Адрес:          {address} ║
    ║ Время:          {time.strftime('%Y-%m-%d %H:%M:%S')} ║
    ╚═══════════════════════════════════════════════════╝
    {Colors.END}
    """
    print(message)
    
    with open("found_keys.txt", "a") as f:
        f.write(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}]")
        f.write(f"\nPrivate: {private_key_hex}")
        f.write(f"\nAddress: {address}")
        f.write("\n" + "="*50 + "\n")

def check_sequential_chunk(start_key, target_address, checked_ranges):
    """Проверяет последовательный блок ключей"""
    end_key = min(start_key + CHUNK_SIZE - 1, MAIN_END)
    found_key = None
    
    # Прогресс-бар для текущего блока
    with tqdm(total=CHUNK_SIZE, desc=f"Checking {hex(start_key)}-{hex(end_key)}", unit="key") as pbar:
        current = start_key
        while current <= end_key:
            private_hex = format(current, '064x')
            address = generate_address(private_hex)
            
            if address == target_address:
                found_key = private_hex
                break
                
            current += 1
            pbar.update(1)
    
    # Сохраняем проверенный диапазон
    if not found_key:
        checked_ranges.append({
            'start': start_key,
            'end': end_key,
            'checked_at': time.strftime('%Y-%m-%d %H:%M:%S')
        })
        save_checked_ranges(checked_ranges)
    
    return found_key

def main():
    target_address = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"
    checked_ranges = load_checked_ranges()
    total_checked = 0
    
    logger.info(f"\n{Colors.YELLOW}=== HYBRID BTC KEY FINDER ==={Colors.END}")
    logger.info(f"Целевой адрес: {target_address}")
    logger.info(f"Диапазон: {hex(MAIN_START)} - {hex(MAIN_END)}")
    logger.info(f"Размер блока: {CHUNK_SIZE:,} ключей")
    logger.info(f"Загружено диапазонов: {len(checked_ranges)}")

    try:
        while True:
            # 1. Генерация случайного непроверенного ключа
            while True:
                random_key = random.randint(MAIN_START, MAIN_END)
                if not is_key_checked(random_key, checked_ranges):
                    break
            
            # 2. Проверка самого случайного ключа
            random_hex = format(random_key, '064x')
            if (address := generate_address(random_hex)) == target_address:
                log_success(random_hex, address)
                break
            total_checked += 1
            
            # 3. Проверка последующих 10M ключей
            if (found_key := check_sequential_chunk(random_key, target_address, checked_ranges)):
                log_success(found_key, target_address)
                break
            total_checked += CHUNK_SIZE
            
    except KeyboardInterrupt:
        logger.info(f"{Colors.YELLOW}\nПоиск остановлен пользователем{Colors.END}")
    finally:
        logger.info(f"Всего проверено ключей: {total_checked:,}")
        logger.info(f"Сохранено диапазонов: {len(checked_ranges)}")
        logger.info("Прогресс сохранен в файл")

if __name__ == "__main__":
    main()
