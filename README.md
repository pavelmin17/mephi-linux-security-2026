# mephi-linux-security-2026

Лабораторная работа по безопасности ОС GNU/Linux: пользователи и группы, мониторинг файлов и процессов, механизмы set-UID, привилегий (capabilities) и sudo.

| | |
|---|---|
| Студент | М265268 |
| GitHub | [pavelmin17](https://github.com/pavelmin17) |
| ОС | Ubuntu (виртуальная машина) |
| Учётная запись администратора | `minaevpd` (UID 1000, группа `sudo`) |

Все команды выполнялись в командной строке от имени root (`sudo -i`). Команды от имени `user1` запускались через `su - user1 -c '...'`, поэтому они тоже записаны в `history.out`.

## Файлы репозитория

| Файл | Раздел | Содержимое |
|---|---|---|
| `mephi-screenshot.png` | 6 | Скриншот терминала с уникальным номером |
| `history.out` | все | История выполненных команд |
| `stat.out` | 1, 3, 4 | `stat` для `/home/user1`, `/home/user1/mycat`, `/home/user1/mychown` |
| `getcap.out` | 4 | Привилегии утилиты `mychown` |
| `find_suid.out` | 2.1 | Файлы с битом set-UID |
| `ps_euid0.out` | 2.2 | Процессы с EUID = 0 и реальным UID обычного пользователя |
| `passwd` | 1 | Копия `/etc/passwd` |
| `shadow` | 1 | Копия `/etc/shadow` |
| `group` | 1 | Копия `/etc/group` |
| `sudoers` | 5 | Копия `/etc/sudoers` |

## Раздел 1. Создание пользователя

| Требование | Команда | Подтверждение |
|---|---|---|
| Группа `students` | `groupadd students` | `group`: `students:x:1001:user1` |
| Пользователь `user1` с UID 1234 | `useradd -m -u 1234 -G students user1` | `passwd`: `user1:x:1234:1234::/home/user1:/bin/sh` |
| `user1` входит в группу `students` | ключ `-G students` при создании | `group`: `students:x:1001:user1` |
| Пароль пользователя | `passwd user1` | `shadow`: у `user1` задан хеш пароля |
| Смена пароля каждые 3 месяца | `chage -M 90 user1` | `shadow`: `user1:<хеш>:20753:0:90:7:::`, 5-е поле — максимальный срок действия пароля (90 дней) |

Проверка: `id user1`, `chage -l user1`.

Основная группа `user1` — одноимённая `user1` (GID 1234), дополнительная — `students` (GID 1001).

Домашняя директория (`stat.out`): `/home/user1`, права `0750 (drwxr-x---)`, владелец `user1:user1`.

## Раздел 2. Мониторинг файлов и процессов

### 2.1. Файлы с битом set-UID

```bash
find / -type f -perm -4000 2>/dev/null | tee ~/find_suid.out
```

`-perm -4000` выбирает файлы с установленным битом set-UID, `2>/dev/null` скрывает сообщения об отказе в доступе.

Результат (`find_suid.out`) — 30 файлов:

- 14 в основной системе: `passwd`, `su`, `sudo`, `mount`, `umount`, `newgrp`, `chfn`, `chsh`, `gpasswd`, `fusermount3`, `ntfs-3g`, `dbus-daemon-launch-helper`, `ssh-keysign`, `polkit-agent-helper-1`;
- 16 внутри слоёв образов контейнеров (`/var/lib/containerd/...`, `/var/lib/docker/...`).

### 2.2. Процессы с EUID = 0 и реальным UID обычного пользователя

На одном терминале обычный пользователь запустил `passwd` и оставил его на запросе текущего пароля. На другом терминале выполнен поиск:

```bash
ps -eo pid,ruid,euid,ruser,euser,cmd | awk 'NR==1 || ($3==0 && $2>=1000 && $2!=65534)' | tee ~/ps_euid0.out
```

Условие `awk`: эффективный UID (3-й столбец) равен 0, а реальный UID (2-й столбец) принадлежит обычному пользователю — от 1000 и выше, кроме `nobody` (65534).

Результат (`ps_euid0.out`):

```
    PID  RUID  EUID RUSER    EUSER    CMD
   4360  1000     0 minaevpd root     sudo -i
   4361  1000     0 minaevpd root     sudo -i
   4572  1000     0 minaevpd root     su - user1
   4585  1234     0 user1    root     passwd
```

Все четыре процесса — программы с битом set-UID: их запустили обычные пользователи (RUID 1000 и 1234), а работают они с правами root (EUID 0).

## Раздел 3. Механизм set-UID

**Утилита:** `cat`.
**Привилегированная операция:** чтение `/etc/shadow`. Этот файл с хешами паролей доступен только root. Пример из задания с `/etc/passwd` не подходит: `/etc/passwd` могут читать все пользователи.

| Шаг | Команда | Результат |
|---|---|---|
| Проверка без привилегий | `su - user1 -c 'cat /etc/shadow'` | `Permission denied` |
| Копия утилиты в директорию пользователя | `cp /usr/bin/cat /home/user1/mycat` | владелец копии — `root` |
| Установка бита set-UID | `chmod u+s /home/user1/mycat` | `-rwsr-xr-x root root` |
| Выполнение операции | `su - user1 -c '/home/user1/mycat /etc/shadow'` | `user1` читает `/etc/shadow` |

`stat.out`: `/home/user1/mycat`, права `4755 (-rwsr-xr-x)`, владелец `root:root`. Цифра 4 — бит set-UID: программа выполняется с правами владельца файла (root), а не того, кто её запустил.

## Раздел 4. Механизм привилегий (capabilities)

**Утилита:** `chown`.
**Привилегированная операция:** передача своего файла другому пользователю. Обычный пользователь этого сделать не может, для этого нужна привилегия `CAP_CHOWN`.

| Шаг | Команда | Результат |
|---|---|---|
| Тестовый файл `user1` | `su - user1 -c 'touch ~/testfile'` | владелец `user1` |
| Проверка без привилегий | `su - user1 -c 'chown root ~/testfile'` | `Operation not permitted` |
| Копия утилиты в директорию пользователя | `cp /usr/bin/chown /home/user1/mychown` | |
| Выдача привилегии | `setcap cap_chown+ep /home/user1/mychown` | |
| Проверка привилегии | `getcap /home/user1/mychown` | `/home/user1/mychown cap_chown=ep` |
| Выполнение операции | `su - user1 -c '/home/user1/mychown root ~/testfile'` | владелец `testfile` — `root` |

`stat.out`: у `/home/user1/mychown` права `0755 (-rwxr-xr-x)`, бита set-UID нет. Операция работает только благодаря привилегии из `getcap.out`: `e` (effective) — привилегия действует сразу при запуске, `p` (permitted) — процессу разрешено её использовать.

**Отличие от set-UID:** `mycat` получает все права root, а `mychown` — только право менять владельца файлов. Так соблюдается принцип минимальных привилегий.

## Раздел 5. Механизм sudo

В `/etc/sudoers` через `visudo` добавлена строка:

```
user1   ALL=(root)   /usr/bin/date, /usr/bin/timedatectl
```

`user1` на любом хосте (`ALL`) может от имени `root` запускать только `date` и `timedatectl`, то есть устанавливать системное время. Остальные команды через sudo ему запрещены.

Проверка:

```bash
sudo -l -U user1                                     # список разрешённых команд
su - user1 -c 'sudo date -s "2026-01-01 12:00:00"'   # время изменено
```

## Раздел 6. Артефакты

- `mephi-screenshot.png` — терминал с уникальным номером `М265268` и результатами работы.
- `stat.out`, `getcap.out`, `history.out`, `find_suid.out`, `ps_euid0.out` — команды, которыми они получены, есть в `history.out`.

## Сохранение настроек после перезагрузки

Все настройки записаны на диск и сохраняются после перезагрузки:

| Настройка | Где хранится |
|---|---|
| Пользователь, группа, срок действия пароля | `/etc/passwd`, `/etc/group`, `/etc/shadow` |
| Бит set-UID | права файла `/home/user1/mycat` |
| Привилегия `cap_chown` | расширенный атрибут `security.capability` файла `/home/user1/mychown` |
| Правило sudo | `/etc/sudoers` |
