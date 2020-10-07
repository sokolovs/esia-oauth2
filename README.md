# esia-oauth2
## Модуль для доступа к ЕСИА REST сервису (https://esia.gosuslugi.ru)
Основан на коде esia-connector https://github.com/eigenmethod/esia-connector, лицензия: https://github.com/eigenmethod/esia-connector/blob/master/LICENSE.txt

### Позволяет:
* Сформировать ссылку для перехода на сайт ЕСИА с целью авторизации
* Завершает процедуру авторизации обменивая временный код на access token
* Опционально может производить JWT (JSON Web Token) валидацию ответа ЕСИА (при наличии публичного ключа ЕСИА)
* Для формирования открепленной подписи запросов, в качестве бэкенда может использоваться
  модуль M2Crypto или openssl через системный вызов (указывается в настройках)
* Выполнять информационные запросы к ЕСИА REST сервису для получения сведений о персоне:
    * Основаная информация
    * Адреса
    * Контактная информация
    * Документы
    * Дети
    * Транспортные средства

### Установка:
```
pip install --upgrade git+https://github.com/sokolovs/esia-oauth2.git
pip install -r https://raw.githubusercontent.com/sokolovs/esia-oauth2/master/requirements.txt
```

### Предварительные условия

Для работы требуется наличие публичного и приватного ключа в соответствии с методическими рекомендациями
по работе с ЕСИА. Допускается использование самоподписного сертифката, который можно сгенерировать
следующей командой:
```
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -sha1 -keyout my_private.key -out my_public_cert.crt
```

Полученный в результате файл my_public_cert.crt должен быть привязан к информационной системе вашей организации
на сайте Госуслуг, а также направлен вместе с заявкой на доступ к ЕСИА
(подробнее см. документы http://minsvyaz.ru/ru/documents/?words=ЕСИА).

**Внимание!** С 01 апреля 2020 прекращается поддержка использования самоподписных сертификатов. Необходимо
получить ключ ГОСТ 2012 в одном из сертификационных центров и использовать алгоритм подписи ГОСТ Р 34.10-2012.
Для этого необходимо установить на сервере КриптоПРО CSP, установить контейнер с закрытым ключем, а так же
привязать сертификат связанный с закрытым ключем к своей информационной системе.

Для валидации ответов от ЕСИА потребуется публичный ключ, который можно запросить в технической поддержке ЕСИА,
уже после регистрации информационной системы и получения доступа к тестовой среде ЕСИА. Валидация опциональна.

### Пример использования в Django

Создайте конфигурационный файл esia.ini следующего содержания:
```
[esia]
### Внимание! Все пути указываются относительно данного файла.
# Базовый адрес сервиса ЕСИА, в данном случае указана тестовая среда
SERVICE_URL: https://esia-portal1.test.gosuslugi.ru

# Идентификатор информационной системы, указывается в заявке на подключение
CLIENT_ID: MYIS01

# Публичный ключ/сертфикат (необязателен, используется только для m2crypto или openssl)
CERT_FILE: keys/my_public_cert.crt

# Приватный ключ (необязателен, используется только для m2crypto или openssl)
PRIV_KEY_FILE: keys/my_private.key

# Публичный ключ сервиса ЕСИА, для валидации ответов (необязателен)
JWT_CHECK_KEY: keys/esia_test_pub.key

# Адрес страницы, на которую будет перенаправлен браузер после авторизации в ЕСИА
REDIRECT_URI: http://127.0.0.1:8000/esia/callback/

# Адрес страницы, на которую необходимо перенаправить браузер после логаута в ЕСИА (опционально)
LOGOUT_REDIRECT_URI: http://127.0.0.1:8000

# Список scope через пробел. Указывается в заявке, openid при авторизации обязателен
SCOPE: openid http://esia.gosuslugi.ru/usr_inf

# Используемый крипто бэкенд: m2crypto, openssl (системный вызов)
# или csp (системный вызов утилиты cryptcp из состава КриптоПРО CSP)
CRYPTO_BACKEND: m2crypto

# SHA1 отпечаток сертификата связанного с закрытым ключем, смотреть по выводу certmgr --list
# (необязателен, используется только для csp)
CSP_CERT_THUMBPRINT: 5c84a6a58bbeb6578ff7d26f4ea65b6de5f9f5b8

# Пароль (пин-код) контейнера с закрктым ключем
# (необязателен, используется только для csp)
CSP_CONTAINER_PWD: 12345678
```

В свой urls.py добавьте:
```python
url(r'^esia/login/$', views.esia_login, name='esia_login'),
url(r'^esia/callback/$', views.esia_callback, name='esia_callback'),
```

В свой views.py добавьте:
```python
import json
from django.http import HttpResponseRedirect, HttpResponse
from django.contrib.auth.views import logout
from esia.client import EsiaConfig, EsiaAuth

ESIA_SETTINGS = EsiaConfig('/full/path/to/esia.ini')

def esia_login(request):
    esia_auth = EsiaAuth(ESIA_SETTINGS)
    esia_login_url = esia_auth.get_auth_url()
    return HttpResponseRedirect(esia_login_url)

def esia_logout(request):
    kwargs = {}
    esia_auth = EsiaAuth(ESIA_SETTINGS)
    kwargs['next_page'] = esia_auth.get_logout_url()
    return logout(request, **kwargs)

def esia_callback(request):
    esia_auth = EsiaAuth(ESIA_SETTINGS)
    if request.GET.has_key('error'):
        data = {
            'error': request.GET['error'],
            'error_description': request.GET['error_description'],
        }
    else:
        data = []
        code = request.GET['code']
        state = request.GET['state']
        esia_client = esia_auth.complete_authorization(code, state)
        # Для отключения JWT валидации ответов ЕСИА, можно так:
        # esia_client = esia_auth.complete_authorization(code, state, validate_token=False)

        # Запрос информации о персоне
        main_info = esia_client.get_person_main_info()
        pers_doc = esia_client.get_person_documents()
        pars_addr = esia_client.get_person_addresses()
        pers_contacts = esia_client.get_person_contacts()
        pers_kids = esia_client.get_person_kids()
        pers_trans = esia_client.get_person_transport()

        data.append(main_info)
        data.append(pers_doc)
        data.append(pars_addr)
        data.append(pers_contacts)
        data.append(pers_kids)
        data.append(pers_trans)

    # Просто выводим информацию. Здесь далее должна идти внутренняя логика авторизации
    # вашей информационной системы.
    return HttpResponse(json.dumps(data, cls=json.JSONEncoder, ensure_ascii=False, indent=4),
        content_type='application/json')
```


### Additional settings
http://pushorigin.ru/cryptopro/cryptcp

Cryptopro server:\n
```
tar -xzf linux-amd64.tgz
cd linux-amd64
sudo ./install.sh


ln -s /opt/cprocsp/bin/amd64/certmgr
ln -s /opt/cprocsp/bin/amd64/cpverify
ln -s /opt/cprocsp/bin/amd64/cryptcp
ln -s /opt/cprocsp/bin/amd64/csptest
ln -s /opt/cprocsp/bin/amd64/csptestf
ln -s /opt/cprocsp/bin/amd64/der2xer
ln -s /opt/cprocsp/bin/amd64/inittst
ln -s /opt/cprocsp/bin/amd64/wipefile
ln -s /opt/cprocsp/sbin/amd64/cpconfig

```
