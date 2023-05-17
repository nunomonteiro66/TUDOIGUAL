from file_cypher import decrypt_file, loadPrivateKey
import sys


if __name__ == "__main__":
    file = sys.argv[1]
    sk = loadPrivateKey()
    msg = decrypt_file(file, sk)
    with open(file, 'r') as f:
        print(f.read())