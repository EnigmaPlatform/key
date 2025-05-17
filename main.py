import hashlib
import random
import base58
import ecdsa
import time
import logging
from multiprocessing import Pool, cpu_count, Manager, Lock
from tqdm import tqdm
import sys

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    END = '\033[0m'

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('btc_key_finder.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def log_success(private_key_hex, btc_address):
    """Функция для вывода сообщения о найденном совпадении"""
    message = f"""
    {Colors.GREEN}
    ╔═══════════════════════════════════════════════════╗
    ║                КЛЮЧ НАЙДЕН!                       ║
    ╠═══════════════════════════════════════════════════╣
    ║ Приватный ключ (HEX): {private_key_hex} ║
    ║ Bitcoin-адрес:       {btc_address} ║
    ║ Время обнаружения:   {time.strftime('%Y-%m-%d %H:%M:%S')} ║
    ╚═══════════════════════════════════════════════════╝
    {Colors.END}
    """
    print(message)
    
    with open("found_key.txt", "a") as f:
        f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}]\n")
        f.write(f"Private Key (HEX): {private_key_hex}\n")
        f.write(f"Address: {btc_address}\n")
        f.write("-" * 50 + "\n\n")

def generate_compressed_address(private_key_hex):
    """Генерирует compressed Bitcoin address"""
    try:
        # Валидация ключа
        if len(private_key_hex) != 64:
            raise ValueError("Invalid key length")
        
        private_key_bytes = bytes.fromhex(private_key_hex)
        
        # Генерация публичного ключа (compressed)
        sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        x = vk.pubkey.point.x()
        y = vk.pubkey.point.y()
        
        # Compressed public key (используем четность y)
        if y % 2 == 0:
            public_key_compressed = bytes.fromhex("02" + "%064x" % x)
        else:
            public_key_compressed = bytes.fromhex("03" + "%064x" % x)
        
        # SHA-256 + RIPEMD-160
        sha256 = hashlib.sha256(public_key_compressed).digest()
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256)
        pubkey_hash = ripemd160.digest()
        
        # Добавляем префикс сети (0x00 для mainnet)
        network_byte = b'\x00'
        extended_hash = network_byte + pubkey_hash
        
        # Контрольная сумма
        checksum = hashlib.sha256(hashlib.sha256(extended_hash).digest()).digest()[:4]
        binary_address = extended_hash + checksum
        
        # Base58 encoding
        address = base58.b58encode(binary_address).decode('utf-8')
        
        return address
    
    except Exception as e:
        logger.error(f"{Colors.RED}Ошибка генерации адреса: {e}{Colors.END}")
        return None

def test_compressed_generation():
    """Тест compressed адресов"""
    test_keys = [
        "000000000000000000000000000000000000000000000000000000000001654f",
        "0000000000000000000000000000000000000000000000000000000000016a4f",
        "000000000000000000000000000000000000000000000000000000000001704f"
    ]
    
    logger.info(f"\n{Colors.YELLOW}=== ТЕСТ COMPRESSED АДРЕСОВ ==={Colors.END}")
    for key in test_keys:
        address = generate_compressed_address(key)
        logger.info(f"Ключ: {key} -> Адрес: {address}")

def worker(args):
    """Функция для worker-процессов"""
    start_int, end_int, target_address, found_flag, counter, lock, chunk_size = args
    keys_checked = 0
    
    while not found_flag.value and keys_checked < chunk_size:
        random_int = random.randint(start_int, end_int)
        private_key_hex = format(random_int, '064x')
        btc_address = generate_compressed_address(private_key_hex)
        
        with lock:
            counter.value += 1
            keys_checked += 1
            
        if btc_address and btc_address == target_address:
            # Используем глобальную функцию log_success
            log_success(private_key_hex, btc_address)
            found_flag.value = True
            return (private_key_hex, keys_checked)
    
    return (None, keys_checked)

def main():
    # Тестирование compressed адресов
    test_compressed_generation()
    
    target_address = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"  # Ваш compressed адрес
    start_range = "0000000000000000000000000000000000000000000000400000000000000000"
    end_range = "00000000000000000000000000000000000000000000007fffffffffffffffff"

    # Проверка и инициализация
    start_int = int(start_range, 16)
    end_int = int(end_range, 16)
    total_keys = end_int - start_int + 1
    chunk_size = 1000

    logger.info(f"\n{Colors.YELLOW}=== ПОИСК СОВПАДЕНИЙ ==={Colors.END}")
    logger.info(f"Ищем: {target_address}")
    logger.info(f"Диапазон: {start_range} - {end_range}")
    logger.info(f"Всего ключей: {total_keys}")

    start_time = time.time()
    
    with Manager() as manager:
        found_flag = manager.Value('b', False)
        counter = manager.Value('i', 0)
        lock = manager.Lock()
        
        try:
            with tqdm(total=total_keys, desc="Прогресс", unit="key") as pbar:
                with Pool(processes=cpu_count()) as pool:
                    args = [(start_int, end_int, target_address, found_flag, counter, lock, chunk_size) 
                           for _ in range(cpu_count())]
                    
                    while not found_flag.value and pbar.n < total_keys:
                        results = pool.imap_unordered(worker, args)
                        total_checked = 0
                        
                        for result, checked in results:
                            total_checked += checked
                            if result is not None:
                                break
                        
                        pbar.update(total_checked)
                        
                        if found_flag.value:
                            break

        except KeyboardInterrupt:
            logger.info(f"{Colors.YELLOW}Остановлено пользователем{Colors.END}")
        finally:
            elapsed_time = time.time() - start_time
            logger.info(f"\nПроверено ключей: {counter.value}")
            logger.info(f"Затрачено времени: {elapsed_time:.2f} сек")
            if not found_flag.value:
                logger.info(f"{Colors.RED}Совпадений не найдено{Colors.END}")

if __name__ == "__main__":
    main()
