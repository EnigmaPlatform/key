from colorama import init, Fore, Style
import psutil
import time
import os
import sys

init(autoreset=True)

class Logger:
    def __init__(self):
        self.lock = threading.Lock()
    
    def log(self, message):
        with self.lock:
            print(message)
            sys.stdout.flush()

logger = Logger()

def print_progress_bar(iteration, total, prefix='', suffix='', length=50, fill='█'):
    """Безопасное отображение прогресс-бара"""
    try:
        total = max(1, total)
        iteration = max(0, min(iteration, total))
        percent = min(100, (iteration / total) * 100)
        filled_length = min(length, int(length * iteration / total))
        bar = fill * filled_length + '-' * (length - filled_length)
        return f"{prefix} |{bar}| {percent:.1f}% {min(iteration, 10**18):,}/{min(total, 10**18):,} {suffix}"
    except Exception as e:
        return f"{prefix} | [ошибка] | {suffix}"
