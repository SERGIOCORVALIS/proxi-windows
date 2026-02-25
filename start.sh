#!/bin/bash

# Проверка Docker
if ! [ -x "$(command -v docker)" ]; then
echo 'Ошибка: Docker не установлен. Устанавливаю...'
curl -fsSL https://get.docker.com | sh
fi

# Запуск сборки
echo "Запускаю прокси-сервер с дашбордом..."
docker compose up -d

echo "------------------------------------------------"
echo "Готово! Панель управления: http://$(curl -s ifconfig.me):2053"
echo "Логин/Пароль: admin / admin"
echo "------------------------------------------------"