# -*- coding: utf-8 -*-
# Код основан на пакете esia-connector
# https://github.com/eigenmethod/esia-connector
# Лицензия:
#   https://github.com/eigenmethod/esia-connector/blob/master/LICENSE.txt
# Copyright (c) 2015, Septem Capital
import os
import os.path
import uuid

try:
    from configparser import RawConfigParser
except ImportError:
    from ConfigParser import RawConfigParser

try:
    from urllib.parse import quote_plus, urlencode
except ImportError:
    from urllib import quote_plus, urlencode

import jwt
from jwt.exceptions import InvalidTokenError

from .exceptions import (
    ConfigFileError, CryptoBackendError, IncorrectMarkerError)

from .utils import get_timestamp, make_request, sign_params


class EsiaSettings(object):
    def __init__(
            self, esia_client_id, redirect_uri, certificate_file,
            private_key_file, esia_service_url, esia_scope,
            crypto_backend='m2crypto', esia_token_check_key=None,
            logout_redirect_uri=None, csp_cert_thumbprint='',
            csp_container_pwd='', ssl_verify=True):
        """
        Класс настроек ЕСИА
        :param str esia_client_id: идентификатор клиента в ЕСИА
            (указывается в заявке)
        :param str redirect_uri: URI по которому браузер будет перенаправлен
            после ввода учетных данны в ЕСИА
        :param str certificate_file: путь к сертификату клиента
            (прилагается к заявке)
        :param str private_key_file: путь к приватному ключу клиента
        :param str esia_service_url: базовый URL сервиса ЕСИА
        :param str esia_scope: список scope, разделенный пробелами, доступный
            клиенту (указывается в заявке)
        :param str or None esia_token_check_key: путь к публичному ключу для
            проверки JWT (access token)
            необходимо запросить у технической поддержки ЕСИА
        :param str crypto_backend: optional, задает крипто бэкенд, может
            принимать значения: m2crypto, openssl, csp
        :param str csp_cert_thumbprint: optional, задает SHA1 отпечаток
            сертификата, связанного с контейнером (отображается по выводу
            certmgr --list), например: 5c84a6a58bbeb6578ff7d26f4ea65b6de5f9f5b8
        :param str csp_container_pwd: optional, пароль для контейнера
            закрытого ключа
        :param boolean ssl_verify: optional, производить ли верификацию
            ssl-сертификата при запросах к сервису ЕСИА?
        """
        self.esia_client_id = esia_client_id
        self.redirect_uri = redirect_uri
        self.certificate_file = certificate_file
        self.private_key_file = private_key_file
        self.esia_service_url = esia_service_url
        self.esia_scope = esia_scope
        self.esia_token_check_key = esia_token_check_key
        self.crypto_backend = crypto_backend
        self.logout_redirect_uri = logout_redirect_uri
        self.csp_cert_thumbprint = csp_cert_thumbprint
        self.csp_container_pwd = csp_container_pwd
        self.ssl_verify = ssl_verify

        if self.crypto_backend == 'csp' and not self.csp_cert_thumbprint:
            raise CryptoBackendError(
                'Crypro backend is "csp" but "CSP_CERT_THUMBPRINT" '
                'variable is empty')


class EsiaConfig(EsiaSettings):
    def __init__(self, config_file, *args, **kwargs):
        """
        Класс настроек ЕСИА на основе конфигурационного файла

        :param str config_file: путь к конфигурационному ini-файлу
        :raises ConfigFileError: если указан неверный путь или файл недоступен
            для чтения
        :raises ConfigParser.*: при ошибках в формате файла или параметра
        """
        if os.path.isfile(config_file) and os.access(config_file, os.R_OK):
            conf = RawConfigParser()
            conf.read(config_file)
            base_dir = os.path.dirname(config_file)

            kwargs = {
                'esia_client_id': conf.get('esia', 'CLIENT_ID'),
                'redirect_uri': conf.get('esia', 'REDIRECT_URI'),
                'esia_service_url': conf.get('esia', 'SERVICE_URL'),
                'esia_scope': conf.get('esia', 'SCOPE'),
                'crypto_backend': conf.get('esia', 'CRYPTO_BACKEND'),
                'certificate_file': None,
                'private_key_file': None,
                'csp_cert_thumbprint': None,
                'csp_container_pwd': None,
                'ssl_verify': True
            }

            # Openssl, M2Crypto params
            if conf.has_option('esia', 'CERT_FILE') and \
                    conf.has_option('esia', 'PRIV_KEY_FILE'):
                cert_f = conf.get('esia', 'CERT_FILE')
                pkey_f = conf.get('esia', 'PRIV_KEY_FILE')
                kwargs['certificate_file'] = base_dir + '/' + cert_f
                kwargs['private_key_file'] = base_dir + '/' + pkey_f

            # CryptoPro CSP params
            if conf.has_option('esia', 'CSP_CERT_THUMBPRINT'):
                kwargs['csp_cert_thumbprint'] = conf.get(
                    'esia', 'CSP_CERT_THUMBPRINT')
                kwargs['csp_container_pwd'] = conf.get(
                    'esia', 'CSP_CONTAINER_PWD')

            if conf.has_option('esia', 'JWT_CHECK_KEY'):
                token_check_key = conf.get('esia', 'JWT_CHECK_KEY')
                kwargs['esia_token_check_key'] = \
                    base_dir + '/' + token_check_key

            if conf.has_option('esia', 'LOGOUT_REDIRECT_URI'):
                redir = conf.get('esia', 'LOGOUT_REDIRECT_URI')
                kwargs['logout_redirect_uri'] = redir

            if conf.has_option('esia', 'SSL_VERIFY'):
                ssl_verify = conf.getboolean('esia', 'SSL_VERIFY')
                kwargs['ssl_verify'] = ssl_verify

            super(EsiaConfig, self).__init__(*args, **kwargs)
        else:
            raise ConfigFileError("Config file not exists or not readable!")


class EsiaAuth(object):
    """
    Класс отвечает за OAuth2 авторизацию черещ ЕСИА
    """
    _ESIA_ISSUER_NAME = 'http://esia.gosuslugi.ru/'
    _AUTHORIZATION_URL = '/aas/oauth2/ac'
    _TOKEN_EXCHANGE_URL = '/aas/oauth2/te'
    _LOGOUT_URL = '/idp/ext/Logout'

    def __init__(self, settings):
        """
        :param EsiaSettings settings: параметры ЕСИА-клиента
        """
        self.settings = settings

    def get_auth_url(self, state=None, redirect_uri=None):
        """
        Возвращает URL для перехода к авторизации в ЕСИА или для
        автоматического редиректа по данному адресу

        :param str or None state: идентификатор, будет возвращен как
            GET параметр в redirected-запросе после авторизации.
        :param str or None redirect_uri: URI, по которому будет
            перенаправлен браузер после авторизации.
        :return: url
        :rtype: str
        """
        params = {
            'client_id': self.settings.esia_client_id,
            'client_secret': '',
            'redirect_uri': redirect_uri or self.settings.redirect_uri,
            'scope': self.settings.esia_scope,
            'response_type': 'code',
            'state': state or str(uuid.uuid4()),
            'timestamp': get_timestamp(),
            'access_type': 'offline'
        }

        params = sign_params(
            params, self.settings,
            backend=self.settings.crypto_backend)

        # sorted needed to make uri deterministic for tests.
        params = urlencode(sorted(params.items()))

        return '{base_url}{auth_url}?{params}'.format(
            base_url=self.settings.esia_service_url,
            auth_url=self._AUTHORIZATION_URL,
            params=params)

    def complete_authorization(
            self, code, state, validate_token=True, redirect_uri=None):
        """
        Завершает авторизацию. Обменивает полученный code на access token.
        При этом может опционально производить JWT-валидацию ответа на основе
        публичного ключа ЕСИА. Извлекает из ответа идентификатор пользователя
        и возвращает экземпляр ESIAInformationConnector для последующих
        обращений за данными пользователя.

        :param str code: Временный код полученный из GET-параметра,
            который обменивается на access token
        :param str state: UUID запроса полученный из GET-параметра
        :param boolean validate_token: производить ли JWT-валидацию
            ответа от ЕСИА
        :param str or None redirect_uri: URI на который браузер был
            перенаправлен после авторизации
        :rtype: EsiaInformationConnector
        :raises IncorrectJsonError: если ответ содержит невалидный JSON
        :raises HttpError: если код HTTP ответа отличен от кода 2XX
        :raises IncorrectMarkerError: если validate_token=True и полученный
            токен не прошел валидацию
        """
        params = {
            'client_id': self.settings.esia_client_id,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': redirect_uri or self.settings.redirect_uri,
            'timestamp': get_timestamp(),
            'token_type': 'Bearer',
            'scope': self.settings.esia_scope,
            'state': state,
        }

        params = sign_params(
            params, self.settings,
            backend=self.settings.crypto_backend
        )

        url = '{base_url}{token_url}'.format(
            base_url=self.settings.esia_service_url,
            token_url=self._TOKEN_EXCHANGE_URL
        )

        response_json = make_request(
            url=url, method='POST', data=params,
            verify=self.settings.ssl_verify)
        id_token = response_json['id_token']

        if validate_token:
            payload = self._validate_token(id_token)
        else:
            payload = self._parse_token(id_token)

        return EsiaInformationConnector(
            access_token=response_json['access_token'],
            oid=self._get_user_id(payload),
            settings=self.settings
        )

    def get_logout_url(self, redirect_uri=None):
        """
        Возвращает URL для выхода пользователя из ЕСИА (логаут)

        :param str or None redirect_uri: URI, по которому будет перенаправлен
            браузер после логаута
        :return: url
        :rtype: str
        """
        logout_url = '{base_url}{logout_url}?client_id={client_id}'.format(
            base_url=self.settings.esia_service_url,
            logout_url=self._LOGOUT_URL,
            client_id=self.settings.esia_client_id
        )

        redirect = (redirect_uri or self.settings.logout_redirect_uri)
        if redirect:
            logout_url += '&redirect_url={redirect}'.format(
                redirect=quote_plus(redirect))

        return logout_url

    @staticmethod
    def _parse_token(token):
        """
        :param str token: токен для декодирования
        :rtype: dict
        """
        return jwt.decode(token, verify=False)

    @staticmethod
    def _get_user_id(payload):
        """
        :param dict payload: декодированные данные токена
        """
        return payload.get('urn:esia:sbj', {}).get('urn:esia:sbj:oid')

    def _validate_token(self, token):
        """
        :param str token: токен для валидации
        """
        if self.settings.esia_token_check_key is None:
            raise ValueError(
                "To validate token you need to specify "
                "`esia_token_check_key` in settings!")

        with open(self.settings.esia_token_check_key, 'r') as f:
            data = f.read()

        try:
            return jwt.decode(
                token, key=data,
                audience=self.settings.esia_client_id,
                issuer=self._ESIA_ISSUER_NAME
            )
        except InvalidTokenError as e:
            raise IncorrectMarkerError(e)


class EsiaInformationConnector(object):
    """
    Класс для получения данных от ЕСИА REST сервиса
    """
    def __init__(self, access_token, oid, settings):
        """
        :param str access_token: access token
        :param int oid: идентификатор объекта в ЕСИА
            (напрамер идентификатор персоны)
        :param EsiaSettings settings: параметры ЕСИА-клиента
        """
        self.token = access_token
        self.oid = oid
        self.settings = settings
        self._rest_base_url = '%s/rs' % settings.esia_service_url

    def esia_request(self, endpoint_url, accept_schema=None):
        """
        Формирует и направляет запрос к ЕСИА REST сервису и возвращает JSON

        :param str endpoint_url: endpoint URL
        :param str or None accept_schema: optional версия схемы ответа
            (влияет на формат ответа)
        :rtype: dict
        :raises IncorrectJsonError: если ответ содержит невалидный JSON
        :raises HttpError: если код HTTP ответа отличен от кода 2XX
        """
        headers = {
            'Authorization': "Bearer %s" % self.token
        }

        if accept_schema:
            headers['Accept'] = 'application/json; schema="%s"' % accept_schema
        else:
            headers['Accept'] = 'application/json'

        return make_request(
            url=endpoint_url, headers=headers,
            verify=self.settings.ssl_verify)

    def get_person_main_info(self, accept_schema=None):
        """
        Возвращает основные сведения о персоне
        :rtype: dict
        """
        url = '{base}/prns/{oid}'.format(
            base=self._rest_base_url, oid=self.oid)
        return self.esia_request(endpoint_url=url, accept_schema=accept_schema)

    def get_person_addresses(self, accept_schema=None):
        """
        Возвращает адреса персоны
        :rtype: dict
        """
        url = '{base}/prns/{oid}/addrs?embed=(elements)'.format(
            base=self._rest_base_url, oid=self.oid)
        return self.esia_request(endpoint_url=url, accept_schema=accept_schema)

    def get_person_contacts(self, accept_schema=None):
        """
        Возвращает контактную информацию персоны
        :rtype: dict
        """
        url = '{base}/prns/{oid}/ctts?embed=(elements)'.format(
            base=self._rest_base_url, oid=self.oid)
        return self.esia_request(endpoint_url=url, accept_schema=accept_schema)

    def get_person_documents(self, accept_schema=None):
        """
        Возвращает документы персоны
        :rtype: dict
        """
        url = '{base}/prns/{oid}/docs?embed=(elements)'.format(
            base=self._rest_base_url, oid=self.oid)
        return self.esia_request(endpoint_url=url, accept_schema=accept_schema)

    def get_person_kids(self, accept_schema=None):
        """
        Возвращает информацию о детях персоны
        :rtype: dict
        """
        url = '{base}/prns/{oid}/kids?embed=(elements)'.format(
            base=self._rest_base_url, oid=self.oid)
        return self.esia_request(endpoint_url=url, accept_schema=accept_schema)

    def get_person_transport(self, accept_schema=None):
        """
        Возвращает информацию о транспортных средствах персоны
        :rtype: dict
        """
        url = '{base}/prns/{oid}//vhls?embed=(elements)'.format(
            base=self._rest_base_url, oid=self.oid)
        return self.esia_request(endpoint_url=url, accept_schema=accept_schema)
