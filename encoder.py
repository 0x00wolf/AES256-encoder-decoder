# This program is an AES-256 cryptographic tool for the command line.
# It uses bit streaming to read in data so it can encrypt large files rapidly.
# There are four modes. See the print_usage function below for more information.
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import sys
import os

default_key_path = './AES256key'
buffer_size = 65536 # 64kb
banner = """
     _____  AES-256 CFB        __                   __ 
   / ____/___  _________  ____/ /__  _____        _/_/ 
  / __/ / __ \/ ___/ __ \/ __  / _ \/ ___/      _/_/   
 / /___/ / / / /__/ /_/ / /_/ /  __/ /        _/_/     
/_____/_/ /_/\___/\____/\__,_/\___/_/    __  /_/       
             / __ \___  _________  ____/ /__  _____
            / / / / _ \/ ___/ __ \/ __  / _ \/ ___/
           / /_/ /  __/ /__/ /_/ / /_/ /  __/ /    
          /_____/\___/\___/\____/\__,_/\___/_/"""

def print_banner():
    print("\n"*40)
    print(banner +"\n")

def print_usage():
    print_banner()
    print('[-] Modes:\n')
    print('-h      display this message')
    print('-e      encrypt')
    print('-d      decrypt')
    print('-k      Generate new AES-256 key to parent directory\n')
    print('[-] Examples:\n')
    print('>>decoder.py -e <./file.type> <./key>')
    print('>>decoder.py -d <./file.type.encrypted> <./key>')
    print('>>decoder.py -k\n')
    sys.exit(0)

def parse_error(e):
    print_banner()
    sys.stderr.write('[!] Error...')
    sys.stderr.write(f'[-] Exception: {e}')
    sys.stderr.write("[+] For usage instructions: encoder.py -h or -help")
    sys.stderr.write('[-] Exiting.')
    sys.exit(1)

def open_file(file_path):
    with open(file_path, 'r') as f:
            message = f.read() 
    return message

def get_key(key_path):
    with open(key_path, 'rb') as f: 
        key = f.read() 
    return key

def generate_key():
    new_key = get_random_bytes(32) # 32 bytes * 8 = 256 bits (1 byte = 8 bits)
    with open(default_key_path, 'wb') as f: 
        f.write(new_key)
    print_banner()
    print('[+] Key successfully written to ./AES256key')
    print('[-] Exiting...')
    sys.exit(0)

def encrypt(file_path, key_path):
    key = get_key(key_path)
    with open(file_path, 'rb') as input_file, \
        open(f'{file_path}.encrypted', 'wb') as output_file:
            cipher = AES.new(key, AES.MODE_CFB)
            output_file.write(cipher.iv)
            buffer = input_file.read(buffer_size)
            while len(buffer) > 0:
                ciphered_bytes = cipher.encrypt(buffer)
                output_file.write(ciphered_bytes)
                buffer = input_file.read(buffer_size)
    # Delete original file? Comment out if no.
    os.remove(file_path)
    print_banner()
    print('[+] File successfully encrypted!.')
    print(f'[+] Encoded file output to: {file_path}.encrypted')
    print('[-] Exiting...')

def decrypt(file_path, key_path):
    remove_suffix = file_path.removesuffix('.encrypted')
    key = get_key(key_path)
    with open(file_path, 'rb') as input_file, \
        open(remove_suffix, 'wb') as output_file:
            iv = input_file.read(16)
            cipher = AES.new(key, AES.MODE_CFB, iv=iv)
            buffer = input_file.read(buffer_size)
            while len(buffer) > 0:
                bytes = cipher.decrypt(buffer)
                output_file.write(bytes)
                buffer = input_file.read(buffer_size)
            input_file.close()
            output_file.close()
    os.remove(file_path)
    print_banner()
    print('\n[+] File successfully decrypted.')
    print(f'[+] Encoded file output to: {remove_suffix}.encrypted')
    print('[-] Exiting...')

def main():
    try:
        mode = sys.argv[1]
        if len(sys.argv) == 2 and mode == '-k':
            generate_key()
        if len(sys.argv) != 4:
            print_usage()
        file_path = sys.argv[2]
        key_path = sys.argv[3]
        if mode == '-e':
            encrypt(file_path, key_path)
        elif mode == '-d':
            decrypt(file_path, key_path)
        else:
            print_usage()
        sys.exit(0)
    except Exception as e:
         parse_error(e)
         
if __name__ == '__main__':
    main()
