# WebShare Security Audit

**Дата на audit:** 2026-01-27
**Последна актуализация:** 2026-01-29
**Версия:** 3.1.7 → 3.2.0 (security fixes)
**Статус:** Фаза 1-3 завършени

---

## Резюме

| Severity | Брой | Поправени |
|----------|------|-----------|
| CRITICAL | 1    | 1 ✅      |
| HIGH     | 5    | 5 ✅      |
| MEDIUM   | 7    | 6 ✅ (1 skip) |
| LOW      | 2    | 2 ✅      |
| **ОБЩО** | **15** | **14** (1 skipped) |

**Skipped:**
- #9 Rate Limiting → Ще се реши с fail2ban

---

## CRITICAL уязвимости

### [x] 1. Plain Text Password Storage ✅ FIXED 2026-01-28
**Файл:** `encryption.php:135,150,172`
**Проблем:** Паролите за криптиране се съхраняват в plain text в `.encryption-keys.json`

**Код с проблем:**
```php
$keys[$filename] = [
    'password_hash' => password_hash($password, PASSWORD_DEFAULT),
    'password_plain' => $password, // ← ПРОБЛЕМ: plain text парола
];
```

**Решение:**
1. Премахни `password_plain` от `storeEncryptionKey()`
2. В `verifyEncryptionPassword()` използвай само `password_verify()`
3. Премахни fallback към plain text сравнение
4. Мигрирай съществуващи записи (изтрий `password_plain` от JSON)

**Стъпки за изпълнение:**
- [ ] Редактирай `storeEncryptionKey()` - премахни password_plain
- [ ] Редактирай `verifyEncryptionPassword()` - премахни fallback
- [ ] Създай миграционен скрипт за изчистване на стари записи
- [ ] Тествай encrypt/decrypt flow

---

## HIGH уязвимости

### [x] 2. Insecure SSL Verification ✅ FIXED 2026-01-28
**Файл:** `web-download.php:90,291`
**Проблем:** SSL сертификатите не се проверяват при изтегляне

**Код с проблем:**
```php
CURLOPT_SSL_VERIFYPEER => false, // ← ПРОБЛЕМ
```

**Решение:**
```php
CURLOPT_SSL_VERIFYPEER => true,
CURLOPT_SSL_VERIFYHOST => 2,
```

**Стъпки за изпълнение:**
- [ ] Промени `CURLOPT_SSL_VERIFYPEER` на `true` (ред 90)
- [ ] Промени `CURLOPT_SSL_VERIFYPEER` на `true` (ред 291)
- [ ] Добави `CURLOPT_SSL_VERIFYHOST => 2`
- [ ] Тествай с HTTPS URLs

---

### [x] 3. Password in GET Parameters ✅ FIXED 2026-01-28
**Файл:** `download.php:75`, `public.php:72`
**Проблем:** Паролата може да се подаде през GET, попада в logs и browser history

**Код с проблем:**
```php
$password = $_POST['decrypt_password'] ?? $_GET['decrypt_password'] ?? null;
```

**Решение:**
```php
$password = $_POST['decrypt_password'] ?? null;
```

**Стъпки за изпълнение:**
- [ ] Премахни `$_GET['decrypt_password']` от download.php
- [ ] Премахни `$_GET['decrypt_password']` от public.php
- [ ] Провери дали има линкове, които разчитат на GET параметъра

---

### [x] 4. Missing CSRF Protection ✅ FIXED 2026-01-28
**Файл:** `index.php` (всички POST форми)
**Проблем:** Липсват CSRF токени, позволява Cross-Site Request Forgery атаки

**Засегнати форми:**
- Добавяне/изтриване на потребители (ред 130-162)
- Запазване на настройки (ред 80-125)
- Upload на файлове
- Изтриване на файлове

**Решение:**
1. Генерирай CSRF token при зареждане на страницата
2. Добави hidden field във всяка форма
3. Валидирай токена при всеки POST

**Код за добавяне:**
```php
// В началото на index.php
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Във всяка форма
<input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">

// При обработка на POST
if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    die('CSRF validation failed');
}
```

**Стъпки за изпълнение:**
- [ ] Добави генериране на CSRF token в session
- [ ] Добави hidden field във всички форми
- [ ] Добави валидация във всички POST handlers
- [ ] Тествай всички форми

---

### [x] 5. API Key Security ✅ FIXED 2026-01-29
**Файл:** `user-management.php`, `api-upload.php`, `index.php`
**Проблем:** Единствен API ключ без IP ограничения

**Решение:**
- Множество API ключове на потребител
- IP binding за всеки ключ (CIDR поддръжка)
- Автоматична миграция на стар формат
- UI за управление на ключове

**Нови функции:**
- `generateApiKey($user, $name, $allowedIps)` - създава ключ с IP ограничения
- `validateApiKey($key, $clientIp)` - валидира ключ + IP
- `updateApiKeyIps($user, $keyId, $ips)` - обновява IP ограничения
- `isIpAllowed($ip, $allowedIps)` - CIDR валидация
- `ipInCidr($ip, $cidr)` - проверка за IP в CIDR range

---

### [x] 6. SMTP Password Visible in HTML ✅ FIXED 2026-01-28
**Файл:** `index.php:2878`
**Проблем:** SMTP паролата е в HTML value атрибут, видима с Developer Tools

**Код с проблем:**
```php
<input type="password" name="smtp_pass" value="<?= htmlspecialchars($mailConfig['smtp_pass'] ?? '') ?>">
```

**Решение:**
```php
<input type="password" name="smtp_pass" value="" placeholder="<?= !empty($mailConfig['smtp_pass']) ? '••••••••' : '' ?>">
```
И при запазване: ако полето е празно, запази старата парола.

**Стъпки за изпълнение:**
- [ ] Промени input полето да не показва стойност
- [ ] Добави placeholder с точки ако има парола
- [ ] Промени save логиката да пази старата парола ако полето е празно
- [ ] Тествай save/load на mail settings

---

## MEDIUM уязвимости

### [x] 7. Weak Token Generation ✅ FIXED 2026-01-28
**Файл:** `share.php:30-38`
**Проблем:** Токените са само 6 символа (~36 bits entropy)

**Код с проблем:**
```php
for ($i = 0; $i < 6; $i++) {
    $token .= $chars[random_int(0, strlen($chars) - 1)];
}
```

**Решение:**
```php
function generateToken() {
    return bin2hex(random_bytes(16)); // 32 символа, 128 bits
}
```

**Стъпки за изпълнение:**
- [ ] Промени generateToken() да генерира 32 символа
- [ ] Тествай споделяне на файлове
- [ ] Старите токени ще продължат да работят

---

### [x] 8. Path Traversal Risk ✅ FIXED 2026-01-28
**Файл:** `download.php:14-24`
**Проблем:** Санитизацията може да се заобиколи с `....//`

**Код с проблем:**
```php
$folder = preg_replace('/\.\./', '', $folder);
```

**Решение:**
```php
// Използвай while цикъл докато няма промяна
do {
    $old = $folder;
    $folder = str_replace(['..', './'], '', $folder);
    $folder = preg_replace('#/+#', '/', $folder); // multiple slashes
} while ($old !== $folder);

// Или по-добре: използвай realpath() и провери дали е в разрешена директория
$realPath = realpath($baseDir . '/' . $folder);
if (strpos($realPath, realpath($baseDir)) !== 0) {
    die('Access denied');
}
```

**Стъпки за изпълнение:**
- [ ] Подобри санитизацията с while цикъл
- [ ] Добави realpath() проверка
- [ ] Тествай с различни path traversal payloads

---

### [ ] 9. Missing Rate Limiting
**Файл:** `share.php:86`, `public.php`
**Проблем:** Няма ограничение на опитите за познаване на токени

**Решение:**
```php
// Използвай файл или session за tracking
$rateLimitFile = __DIR__ . '/.rate-limit.json';
$limits = json_decode(file_get_contents($rateLimitFile), true) ?? [];
$ip = $_SERVER['REMOTE_ADDR'];
$now = time();

// Изчисти стари записи
$limits = array_filter($limits, fn($t) => $t > $now - 3600);

// Провери лимит (100 опита на час)
$ipAttempts = count(array_filter($limits, fn($k) => str_starts_with($k, $ip)));
if ($ipAttempts > 100) {
    http_response_code(429);
    die('Too many requests');
}

$limits[$ip . '_' . $now] = $now;
file_put_contents($rateLimitFile, json_encode($limits));
```

**Стъпки за изпълнение:**
- [ ] Създай rate limiting функция
- [ ] Приложи в share.php и public.php
- [ ] Тествай с множество заявки

---

### [x] 10. Missing Security Headers ✅ FIXED 2026-01-28
**Файл:** Всички PHP файлове
**Проблем:** Липсват HTTP security headers

**Решение - създай `security-headers.php`:**
```php
<?php
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');

if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}
```

**Стъпки за изпълнение:**
- [ ] Създай security-headers.php
- [ ] Включи го в началото на index.php
- [ ] Включи го в другите публични endpoints
- [ ] Тествай с securityheaders.com

---

### [x] 11. Session Fixation ✅ FIXED 2026-01-28
**Файл:** `index.php:11`
**Проблем:** Няма регенериране на session ID при login

**Решение:**
```php
session_start();

// След успешна автентикация (веднъж per session)
if (!isset($_SESSION['regenerated'])) {
    session_regenerate_id(true);
    $_SESSION['regenerated'] = true;
}
```

**Стъпки за изпълнение:**
- [ ] Добави session_regenerate_id() след login
- [ ] Тествай login flow

---

### [x] 12. Weak File Upload Validation ✅ FIXED 2026-01-28
**Файл:** `api-upload.php:58-63`
**Проблем:** Валидира се само име, не и съдържание

**Текущ код:**
```php
$originalName = basename($file['name']);
```

**Решение:**
```php
// Забранени разширения
$dangerousExtensions = ['php', 'phtml', 'php3', 'php4', 'php5', 'phps', 'phar', 'htaccess'];
$ext = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));

if (in_array($ext, $dangerousExtensions)) {
    die('File type not allowed');
}

// Проверка на MIME type
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mimeType = finfo_file($finfo, $file['tmp_name']);
finfo_close($finfo);

// Опасни MIME types
if (strpos($mimeType, 'php') !== false || $mimeType === 'text/x-php') {
    die('File type not allowed');
}
```

**Стъпки за изпълнение:**
- [ ] Добави списък със забранени разширения
- [ ] Добави MIME type проверка
- [ ] Тествай upload на различни файлове

---

### [x] 13. Command Execution ✅ VERIFIED SECURE 2026-01-29
**Файл:** `user-management.php:55-123`
**Проблем:** Използва exec() за htpasswd

**Текущ код:**
```php
exec($cmd, $output, $returnCode);
```

**Статус:** БЕЗОПАСНО - правилно защитено:
- Username validation: `/^[a-zA-Z0-9_-]{3,20}$/`
- Всички параметри: `escapeshellarg()`
- exec() е необходим за Apache APR1-MD5 формат

**Решение (алтернатива без exec):**
```php
// Използвай password_hash() директно
function addUserDirect($username, $password) {
    $hash = password_hash($password, PASSWORD_BCRYPT);
    // APR1 format за Apache: използвай библиотека или custom функция
}
```

**Стъпки за изпълнение:**
- [ ] Разгледай възможност за премахване на exec()
- [ ] Или добави допълнителна валидация на input
- [ ] Документирай защо exec() е необходим

---

## LOW уязвимости

### [x] 14. Timing Attack on Password ✅ FIXED with #1 (2026-01-28)
**Файл:** `encryption.php:172`
**Проблем:** String comparison е vulnerable на timing attacks

**Статус:** ПОПРАВЕНО - `password_plain` е премахнато изцяло.
Сега се използва само `password_verify()` който е timing-safe.

---

### [x] 15. Race Condition in File Naming ✅ FIXED 2026-01-29
**Файл:** `api-upload.php`, `index.php`, `upload.php`, `web-download.php`, `folder-management.php`
**Проблем:** TOCTOU (Time-of-check to time-of-use) race condition

**Стар код:**
```php
while (file_exists($targetPath)) {
    $counter++;
    $targetPath = $uploadDir . $baseName . '_' . $counter . $ext;
}
```

**Нов код:**
```php
$uniqueId = bin2hex(random_bytes(4)); // 8 hex chars
$finalName = $baseName . '_' . $uniqueId . $ext;
```

**Поправени файлове:**
- api-upload.php
- index.php (getUniqueFilename)
- upload.php (getUniqueFilename)
- web-download.php (2 места)
- folder-management.php (2 места)

---

## Тестови Payloads

### Path Traversal тестове:
```
../../../etc/passwd
....//....//etc/passwd
..%2f..%2f..%2fetc/passwd
..%252f..%252f..%252fetc/passwd
```

### XSS тестове:
```
<script>alert('XSS')</script>
"><script>alert('XSS')</script>
' onmouseover='alert(1)'
```

### CSRF тест:
```html
<form action="https://target.com/index.php" method="POST">
    <input type="hidden" name="user_action" value="add">
    <input type="hidden" name="new_username" value="hacker">
    <input type="hidden" name="new_password" value="hacked123">
    <input type="submit" value="Click me!">
</form>
```

---

## История на промените

| Дата | Версия | Поправени issues | Бележки |
|------|--------|------------------|---------|
| 2026-01-27 | 3.1.7 | - | Initial audit |
| 2026-01-28 | 3.1.8 | #1,#2,#3,#4,#6,#7,#8,#10,#11,#12 | Фаза 1+2 |
| 2026-01-29 | 3.1.8 | #13,#14,#15 + text tokens | Фаза 3 + fixes |

## Допълнителни поправки (2026-01-29)

- **Text sharing tokens:** Променени от 6 на 32 символа
- **.htaccess:** Обновен regex за text tokens `{6,64}`
- **t.php:** Добавен бутон "Затвори", `hash_equals()` за edit key
- **Sync:** Всички промени синхронизирани с `installer/src/`

---

## Следващи стъпки

1. **Фаза 1 (CRITICAL + HIGH):** Issues #1, #2, #3, #4, #6
2. **Фаза 2 (MEDIUM):** Issues #7, #8, #9, #10, #11, #12
3. **Фаза 3 (LOW + Cleanup):** Issues #13, #14, #15
4. **Финално тестване:** Penetration test на всички поправки
