import asyncio
import struct
import socket
import logging

# === ЛЁГКАЯ НАСТРОЙКА ===
HOST = '0.0.0.0'      # 0.0.0.0 — слушать на всех интерфейсах (доступ извне)
PORT = 1080           # Порт прокси-сервера
USERNAME = 'admin'    # Ваш логин
PASSWORD = 'password' # Ваш пароль
# ========================

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

async def handle_client(reader, writer):
    client_addr = writer.get_extra_info('peername')
    try:
        # 1. Приветствие SOCKS5
        version, nmethods = struct.unpack("!BB", await reader.readexactly(2))
        methods = await reader.readexactly(nmethods)

        # Проверка поддержки метода аутентификации по логину/паролю (0x02)
        if b'\x02' not in methods:
            writer.write(b'\x05\xff')
            await writer.drain()
            return
            
        writer.write(b'\x05\x02')
        await writer.drain()

        # 2. Аутентификация
        auth_version = await reader.readexactly(1)
        user_len = struct.unpack("!B", await reader.readexactly(1))[0]
        user = (await reader.readexactly(user_len)).decode()
        
        pass_len = struct.unpack("!B", await reader.readexactly(1))[0]
        password = (await reader.readexactly(pass_len)).decode()

        if user != USERNAME or password != PASSWORD:
            logging.warning(f"Неудачная попытка входа от {client_addr}")
            writer.write(b'\x01\x01') # Отказ
            await writer.drain()
            return

        writer.write(b'\x01\x00') # Успех
        await writer.drain()

        # 3. Обработка запроса на подключение
        version, cmd, _, address_type = struct.unpack("!BBBB", await reader.readexactly(4))
        if cmd != 1: # Поддерживаем только команду CONNECT (1)
            return

        if address_type == 1: # IPv4
            address = socket.inet_ntoa(await reader.readexactly(4))
        elif address_type == 3: # Доменное имя
            domain_len = struct.unpack("!B", await reader.readexactly(1))[0]
            address = (await reader.readexactly(domain_len)).decode()
        else:
            return # IPv6 не поддерживается в этой базовой версии

        port = struct.unpack("!H", await reader.readexactly(2))[0]
        logging.info(f"Подключение: {client_addr} -> {address}:{port}")

        # 4. Подключение к целевому серверу
        try:
            remote_reader, remote_writer = await asyncio.open_connection(address, port)
            # Сообщаем клиенту, что соединение установлено
            bind_addr = socket.inet_aton('0.0.0.0')
            writer.write(b'\x05\x00\x00\x01' + bind_addr + struct.pack("!H", 0))
            await writer.drain()
        except Exception as e:
            logging.error(f"Ошибка подключения к {address}:{port} - {e}")
            writer.write(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()
            return

        # 5. Проксирование трафика (пересылка данных в обе стороны)
        async def relay(r, w):
            try:
                while True:
                    data = await r.read(8192)
                    if not data:
                        break
                    w.write(data)
                    await w.drain()
            except Exception:
                pass
            finally:
                w.close()

        await asyncio.gather(
            relay(reader, remote_writer),
            relay(remote_reader, writer)
        )

    except asyncio.IncompleteReadError:
        pass # Клиент отключился
    except Exception as e:
        logging.debug(f"Ошибка соединения с {client_addr}: {e}")
    finally:
        writer.close()

async def main():
    server = await asyncio.start_server(handle_client, HOST, PORT)
    logging.info(f"Прокси-сервер запущен на {HOST}:{PORT}")
    logging.info(f"Логин: {USERNAME} | Пароль: {PASSWORD}")
    
    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nСервер остановлен.")
