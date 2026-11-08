# Архивиране на WebShare

| | |
|---|---|
| Скрипт | `tools/webshare-backup.sh` в хранилището, инсталиран в `/usr/local/sbin/webshare-backup.sh` |
| Стартира се | всеки ден в 03:30 от `/etc/cron.d/webshare-backup` |
| Цел | `/var/backups/webshare/`, root, 700 |
| Лог | `/var/log/webshare-backup.log`, ротира се месечно |
| Настройки | по желание в `/etc/default/webshare-backup` |

## Какво се пази

| Част | Как | Колко дълго |
|---|---|---|
| `files/` и `texts/` | rsync snapshot в `data/ГГГГ-ММ-ДД_ЧЧММ/`. Непроменените файлове са hard links към предишния snapshot и не заемат място. | 14 snapshot-а (`KEEP_DATA`) |
| Метаданни: потребители, споделяния, ключове за криптиране, API ключове, конфигурация, одит, Upload Guard | `meta/meta-<дата>.tar.gz` от всички обикновени dot файлове в корена и в `src/`. Симлинковете се пропускат, а `.git` се изключва. | 30 архива (`KEEP_META`) |

Сесиите не се пазят нарочно. След възстановяване потребителите просто влизат отново.

**Измерено на 2026-11-08:**
- Първият snapshot е 16 GB и отнема 19 s.
- Вторият е 68 KB и отнема 0,1 s.
- Списъкът с файлове и контролната сума на проверения файл съвпадат с оригинала.

## Защити в скрипта

- `flock`: два архива не могат да вървят едновременно.
- Отказ при под 5 GB свободно място на целта.
- Snapshot-ът се пише като `.partial` и се преименува чак при успех. Недовършен snapshot се трие при следващото пускане и никога не се ползва за основа.
- `umask 077`: архивът е четим само от root.
- При грешка cron праща имейл на root.

## Възстановяване

```bash
# Един файл
cp -a /var/backups/webshare/data/2026-11-08_2149/files/admin/name.pdf /var/www/webshare/files/admin/

# Цяла папка на потребител
rsync -a /var/backups/webshare/data/<snapshot>/files/alice/ /var/www/webshare/files/alice/

# Метаданни (в отделна папка, после се копира нужният файл)
mkdir /tmp/restore && tar -xzf /var/backups/webshare/meta/meta-<дата>.tar.gz -C /tmp/restore
cp /tmp/restore/.folder-shares.json /var/www/webshare/ && chown www-data:www-data /var/www/webshare/.folder-shares.json && chmod 600 /var/www/webshare/.folder-shares.json

webshare-backup.sh --list     # наличните snapshot-и
```

## Защо копието е на същия диск

Сървърът е VM, която се архивира от Proxmox. Отказ на диска или загуба на машината се покрива от архива на VM-а, а кодът е и в git. Локалните snapshot-и дават бързо връщане на отделен файл или папка към конкретен ден, без възстановяване на цялата машина. Те пазят от изтриване, грешка на потребителя или бъг като почистването на сесиите (D-012).

Второ копие не е нужно. Ако все пак потрябва, скриптът поддържа `EXTRA_DEST=/път` в `/etc/default/webshare-backup`.
