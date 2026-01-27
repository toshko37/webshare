# WebShare

**WebShare** е просто, самостоятелно хоствано приложение за споделяне на файлове с поддръжка на множество потребители, организация в папки, криптиране на файлове и споделяне по имейл.

## Функции

### Управление на файлове
- **Качване с Drag & Drop** - Качване на файлове чрез плъзгане в браузъра
- **Система от папки** - Организация на файлове в потребителски папки и подпапки (до 3 нива)
- **Операции с файлове** - Преименуване, преместване, изтриване на файлове
- **Споделяне на файлове** - Генериране на публични линкове с опционално изтичане
- **Web Download** - Сваляне на файлове от URL директно на сървъра

### Сигурност
- **Удостоверяване** - Apache Basic Auth с .htpasswd
- **Криптиране на файлове** - AES-256-GCM криптиране за чувствителни файлове
- **GeoIP Филтриране** - Ограничаване на достъпа по държава
- **CSRF Защита** - Всички форми са защитени срещу CSRF атаки
- **Одит логове** - Проследяване на всички действия на потребителите

### Споделяне
- **Публични линкове** - Споделяне на файлове чрез token-базирани URL-и
- **Споделяне по имейл** - Изпращане на линкове за споделяне по имейл (SMTP)
- **Споделяне на текст** - Споделяне на форматиран текст със синтактично оцветяване

### Допълнителни
- **Многоезичен интерфейс** - Поддръжка на множество езици
- **Респонсивен дизайн** - Работи на десктоп и мобилни устройства
- **Без база данни** - Всички данни се съхраняват в JSON файлове

## Изисквания

### Минимални
- PHP 7.4 или по-висока версия
- Apache с mod_rewrite
- 50MB дисково пространство (плюс място за файлове)

### Препоръчителни
- PHP 8.0+
- php-xml (за DOMDocument)
- php-curl (за web download)
- php-mbstring (за обработка на текст)
- php-maxminddb (за GeoIP)

## Инсталация

### Метод 1: Отдалечена инсталация (Препоръчително)

```bash
curl -fsSL https://webshare.techbg.net/get | bash
```

### Метод 2: Локална инсталация (Ръчно копиране)

1. Копирайте папката WebShare на вашия уеб сървър
2. Стартирайте скрипта за локална инсталация:
```bash
cd /път/до/webshare
sudo ./install-local.sh
```

### Метод 3: Ръчна инсталация

1. Изтеглете/клонирайте файловете на WebShare
2. Създайте необходимите директории:
```bash
mkdir -p files/_public files/admin texts assets/quill
```
3. Създайте admin потребител:
```bash
htpasswd -c .htpasswd admin
```
4. Задайте права:
```bash
chown -R www-data:www-data .
chmod 755 . files texts assets
chmod 644 *.php .htaccess
chmod 600 .*.json
```

## Конфигурация

### Apache Virtual Host

```apache
<VirtualHost *:80>
    ServerName webshare.example.com
    DocumentRoot /var/www/webshare

    <Directory /var/www/webshare>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
```

### SSL (Препоръчително)

```apache
<VirtualHost *:443>
    ServerName webshare.example.com
    DocumentRoot /var/www/webshare

    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/webshare.example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/webshare.example.com/privkey.pem

    <Directory /var/www/webshare>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
```

### Настройки за имейл (По избор)

Конфигурирайте в таб Настройки:
- SMTP Хост (напр. mail.example.com)
- SMTP Порт (465 за SSL, 587 за TLS)
- SMTP Потребител
- SMTP Парола
- Криптиране (SSL/TLS)

### GeoIP Настройки (По избор)

Създайте `.geo.json`:
```json
{
    "enabled": true,
    "allowed_countries": ["BG", "US", "DE"],
    "blocked_countries": [],
    "allow_unknown": false
}
```

## Файлова структура

```
webshare/
├── index.php           # Главно приложение
├── upload.php          # Обработка на качване
├── download.php        # Обработка на сваляне
├── share.php           # Генератор на споделени линкове
├── public.php          # Публичен достъп до файлове
├── text.php            # Бекенд за съхранение на текст
├── t.php               # Интерфейс за споделяне на текст
├── send-mail.php       # API за изпращане на имейл
├── web-download.php    # Обработка на URL сваляне
├── .htaccess           # Apache конфигурация
├── .htpasswd           # Потребителски данни
├── .config.json        # Конфигурация на сайта
├── .geo.json           # GeoIP конфигурация
├── files/              # Потребителски файлове
│   ├── _public/        # Публична папка
│   └── [username]/     # Потребителски папки
├── texts/              # Споделени текстове
└── assets/             # Статични ресурси
    └── quill/          # Quill.js редактор
```

## Обновяване

### Автоматично обновяване

```bash
cd /път/до/webshare
./update.sh
```

### Ръчно обновяване

Изтеглете новите файлове и ги заменете, като запазите:
- `files/` директория
- `texts/` директория
- `.htpasswd`
- `.config.json`
- `.geo.json`
- `GeoLite2-Country.mmdb`

## Отстраняване на проблеми

### 500 Internal Server Error
- Проверете Apache error log: `tail -f /var/log/apache2/error.log`
- Проверете дали PHP е инсталиран: `php -v`
- Проверете дали .htaccess е разрешен: `AllowOverride All` в Apache config

### 403 Forbidden
- Проверете правата на файловете: `ls -la`
- Проверете дали .htpasswd съществува и е четим

### Файловете не се качват
- Проверете PHP лимитите за качване в `.htaccess` или `php.ini`
- Проверете дали `files/` директорията е записваема

### GeoIP не работи
- Инсталирайте php-maxminddb: `apt install php-maxminddb`
- Изтеглете базата данни: `GeoLite2-Country.mmdb`

### Имейлът не се изпраща
- Проверете SMTP настройките в таб Настройки
- Проверете MX записите за домейна на получателя
- Тествайте с бутона Test преди запазване

## Препоръки за сигурност

1. **Използвайте HTTPS** - Винаги използвайте SSL/TLS в продукция
2. **Силни пароли** - Използвайте силни пароли за всички потребители
3. **Редовни обновявания** - Поддържайте WebShare и PHP актуални
4. **Архивиране** - Редовно архивирайте `files/`, `.htpasswd` и конфигурационните файлове
5. **Firewall** - Ограничете достъпа до доверени IP адреси, ако е възможно
6. **fail2ban** - Конфигурирайте fail2ban за защита от brute-force атаки

## Лиценз

MIT License - Вижте файла LICENSE за детайли.

---

**WebShare** - Просто и сигурно споделяне на файлове.
