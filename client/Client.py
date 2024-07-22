import socket
import threading
from cryptography.hazmat.primitives import serialization
from key_utils import generate_rsa_keys, get_session_key
from crypto_utils import encrypt_message, decrypt_message
from colorama import init, Fore

# Настройки клиента
host = 'localhost'
port = 12345

init(autoreset=True)

# Генерация RSA ключей
client_private_key, client_public_key = generate_rsa_keys()


def handle_server(server_socket, session_k):
    def recv_message():
        while True:
            try:
                encrypted_message = server_socket.recv(256)
                if not encrypted_message:
                    print(Fore.RED + "\nСервер отключился")
                    exit()

                message = decrypt_message(encrypted_message, session_k)
                print(Fore.CYAN + f"\nСервер: {message}")
                print('Вы:', end='\t')
            except ConnectionError:
                print(Fore.RED + "\nСервер отключился")
                break
        server_socket.close()

    def send_message():
        while True:
            try:
                message = input("Вы: ")
                encrypted_message = encrypt_message(message, session_k)
                server_socket.sendall(encrypted_message)
            except ConnectionError:
                print(Fore.RED + "Не удалось отправить сообщение, сервер отключился")
                break
            except UnicodeDecodeError:
                break

    recv_thread = threading.Thread(target=recv_message)
    send_thread = threading.Thread(target=send_message)

    recv_thread.start()
    send_thread.start()
    try:
        recv_thread.join()
        send_thread.join()
    except KeyboardInterrupt:
        pass


# Подключение к серверу
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((host, port))
print(Fore.GREEN + "Соединение установлено")

# Получение публичного ключа сервера
server_public_key = serialization.load_pem_public_key(client.recv(1024))

# Отправка публичного ключа клиента серверу
client.sendall(client_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
))

# Получение зашифрованного AES ключа от сервера
encrypted_aes_key = client.recv(256)
session_key = get_session_key(encrypted_aes_key, client_private_key)

try:
    handle_server(client, session_key)
except KeyboardInterrupt:
    pass
