import hashlib
import random
import base58
import ecdsa
import time
import logging
from multiprocessing import Pool, cpu_count
from tqdm import tqdm
import sys

# Настройка красивого вывода
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

def generate_btc_address(private_key_hex):
    try:
        private_key_bytes = bytes.fromhex(private_key_hex)
        sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        public_key_bytes = b'\x04' + vk.to_string()
        
        sha256 = hashlib.sha256(public_key_bytes).digest()
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256)
        pubkey_hash = ripemd160.digest()
        
        network_byte = b'\x00'
        extended_hash = network_byte + pubkey_hash
        checksum = hashlib.sha256(hashlib.sha256(extended_hash).digest()[:4]
        binary_address = extended_hash + checksum
        
        return base58.b58encode(binary_address).decode('utf-8')
    except Exception as e:
        logger.error(f"{Colors.RED}Ошибка генерации адреса: {e}{Colors.END}")
        return None

def log_success(private_key_hex, btc_address):
    """Яркое сообщение о найденном совпадении"""
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
    
    # Запись в файл
    with open("found_key.txt", "a") as f:
        f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}]\n")
        f.write(f"Private Key (HEX): {private_key_hex}\n")
        f.write(f"Address: {btc_address}\n")
        f.write("-" * 50 + "\n\n")

def check_private_key(private_key_hex, target_address):
    btc_address = generate_btc_address(private_key_hex)
    if btc_address == target_address:
        log_success(private_key_hex, btc_address)
        return True
    return False

def generate_and_check(start_int, end_int, target_address, progress_bar):
    while True:
        try:
            random_int = random.randint(start_int, end_int)
            private_key_hex = format(random_int, '064x')
            if check_private_key(private_key_hex, target_address):
                progress_bar.close()
                return private_key_hex
            progress_bar.update(1)
        except Exception as e:
            logger.error(f"{Colors.RED}Ошибка: {e}{Colors.END}")

def main():
    target_address = "1HduPEXZRdG26SUT5Yk83mLkPyjnZuJ7Bm"  # Замените на нужный адрес
    start_range = "000000000000000000000000000000000000000000000000000000000001754f"
    end_range = "000000000000000000000000000000000000000000000000000000000001764f"

    start_int = int(start_range, 16)
    end_int = int(end_range, 16)

    logger.info(f"{Colors.YELLOW}🔍 Поиск адреса: {target_address}{Colors.END}")
    logger.info(f"Диапазон ключей: от {start_range} до {end_range}")

    start_time = time.time()
    total_keys = 100000  # Примерное количество ключей для прогресс-бара

    try:
        with tqdm(total=total_keys, desc="Перебор ключей", unit="key") as pbar:
            with Pool(processes=cpu_count()) as pool:
                args = [(start_int, end_int, target_address, pbar) for _ in range(cpu_count())]
                pool.starmap(generate_and_check, args)
    except KeyboardInterrupt:
        logger.info(f"{Colors.YELLOW}Скрипт остановлен пользователем.{Colors.END}")
    finally:
        elapsed_time = time.time() - start_time
        logger.info(f"Завершено за {elapsed_time:.2f} секунд")

if __name__ == "__main__":
    main()
