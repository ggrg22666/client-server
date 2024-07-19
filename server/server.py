import socket
import threading
import os
from cryptography.hazmat.primitives import serialization
from key_utils import generate_rsa_keys, get_encrypted_aes_key
from crypto_utils import encrypt_message, decrypt_message

# Настройки сервера
host = '192.168.8.140'
port = 12345

# Генерация RSA ключей
server_private_key, server_public_key = generate_rsa_keys()


def handle_client(client_sock):
    def recv_message():
        while True:
            try:
                encrypted_message = client_sock.recv(256)
                if not encrypted_message:
                    print("\nКлиент отключился")
                    print("Ожидание нового клиента...")
                    break

                message = decrypt_message(encrypted_message, session_keys[client_sock])
                print(f"\nКлиент: {message}")
                print("Вы:", end='\t')
            except ConnectionError:
                print("\nКлиент отключился")
                print("Ожидание нового клиента...")
                break
        client_sock.close()

    def send_message():
        while True:
            try:
                message = input("Вы: ")
                encrypted_message = encrypt_message(message, session_keys[client_sock])
                client_sock.sendall(encrypted_message)
            except ConnectionError:
                print("Не удалось отправить сообщение, клиент отключился")
                print("Ожидание нового клиента...")
                break
            except UnicodeDecodeError:
                break

    # Получение публичного ключа клиента
    client_public_key = serialization.load_pem_public_key(client_sock.recv(1024))

    # Генерация симметричного ключа AES
    aes_key = os.urandom(32)
    session_keys[client_sock] = aes_key

    # Шифрование AES ключа с помощью публичного ключа клиента
    encrypted_aes_key = get_encrypted_aes_key(aes_key, client_public_key)

    # Отправка зашифрованного AES ключа клиенту
    client_sock.sendall(encrypted_aes_key)

    recv_thread = threading.Thread(target=recv_message)
    send_thread = threading.Thread(target=send_message)

    recv_thread.start()
    send_thread.start()

    recv_thread.join()
    send_thread.join()


# Запуск сервера
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen(5)
print(f"Сервер запущен на {host}:{port}")

session_keys = {}

while True:
    try:
        client_socket, addr = server.accept()
        print(f"Подключен клиент {addr}")

        # Отправка публичного ключа сервера
        client_socket.sendall(server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()
    except KeyboardInterrupt:
        server.close()
        break
