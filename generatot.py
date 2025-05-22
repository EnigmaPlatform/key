import hashlib
import multiprocessing
import coincurve
import os
import random
from multiprocessing import Pool, cpu_count

CONFIG = {
    'TARGET_RIPEMD': bytes.fromhex("f6f5431d25bbf7b12e8add9af5e3475c44a0a5b8"),
    'LEADING_ZEROS': '0' * 46,
    'FIRST_CHAR': ['6', '7'],
    'WORKERS': max(8, cpu_count()),
    'REPORT_INTERVAL': 100_000,
    'TEST_KEY': "0000000000000000000000000000000000000000000000000000000000000001"
}

def test_hashing():
    test_key = CONFIG['TEST_KEY']
    expected_hash = "751e76e8199196d454941c45d1b3a323f1433bd6"
    
    private_key = bytes.fromhex(test_key)
    public_key = coincurve.PublicKey.from_secret(private_key).format(compressed=True)
    sha256 = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new('ripemd160', sha256).digest()
    
    if ripemd160.hex() == expected_hash:
        print(f"[TEST] Hash correct: {expected_hash}")
        return True
    print("[TEST] Hash mismatch!")
    return False

def generate_high_entropy_key():
    """Генерация 64-символьного ключа с высокой энтропией"""
    random_part = os.urandom(9).hex()[:17]  # 9 байт = 18 символов, берем 17
    return CONFIG['LEADING_ZEROS'] + random.choice(CONFIG['FIRST_CHAR']) + random_part

def worker(worker_id):
    """Рабочая функция без разделяемых объектов"""
    local_count = 0
    
    while True:
        key = generate_high_entropy_key()
        
        try:
            private_key = bytes.fromhex(key)
            public_key = coincurve.PublicKey.from_secret(private_key).format(compressed=True)
            sha256 = hashlib.sha256(public_key).digest()
            ripemd160 = hashlib.new('ripemd160', sha256).digest()
            
            if ripemd160 == CONFIG['TARGET_RIPEMD']:
                print(f"\n\n[SUCCESS] Worker {worker_id} found matching key:")
                print(f"PRIVATE KEY: {key}")
                print(f"ADDRESS HASH: {ripemd160.hex()}")
                return key
                
            local_count += 1
            if local_count % CONFIG['REPORT_INTERVAL'] == 0:
                print(f"Worker {worker_id} processed: {local_count:,} keys")
                
        except Exception as e:
            print(f"Worker {worker_id} error: {str(e)}")
            continue

def main():
    print(f"[SYSTEM] CPU cores: {cpu_count()}")
    print(f"[CONFIG] Workers: {CONFIG['WORKERS']}")
    print(f"[TARGET] Searching for: {CONFIG['TARGET_RIPEMD'].hex()}")
    
    if not test_hashing():
        return
    
    print("\n[START] Beginning search with high entropy keys...")
    print("Example generated keys:")
    for _ in range(5):
        print(generate_high_entropy_key())
    print("\nWorkers are running...\n")
    
    try:
        with Pool(CONFIG['WORKERS']) as pool:
            results = []
            for i in range(CONFIG['WORKERS']):
                res = pool.apply_async(worker, (i+1,))
                results.append(res)
            
            # Ожидаем завершения любого worker
            for res in results:
                try:
                    found_key = res.get()
                    if found_key:
                        break
                except KeyboardInterrupt:
                    print("\n[STOP] Interrupted by user")
                    break
                    
    except Exception as e:
        print(f"\n[ERROR] {str(e)}")
    finally:
        print("\n[STATS] Search finished")

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
