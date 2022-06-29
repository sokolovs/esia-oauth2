# -*- coding: utf-8 -*-
# Код основан на пакете esia-connector
# https://github.com/eigenmethod/esia-connector
# Лицензия:
#   https://github.com/eigenmethod/esia-connector/blob/master/LICENSE.txt
# Copyright (c) 2015, Septem Capital
import base64
import datetime
import json
import os
import tempfile

import pytz

import requests

from .exceptions import CryptoBackendError, HttpError, IncorrectJsonError


def make_request(url, method='GET', headers=None, data=None, verify=True):
    """
    Выполняет запрос по заданному URL и возвращает dict на основе JSON-ответа

    :param str url: URL-адрес
    :param str method: (optional) HTTP-метод запроса, по умолчанию GET
    :param dict headers: (optional) массив HTTP-заголовков, по умолчанию None
    :param dict data: (optional) массив данных передаваемых в запросе,
        по умолчанию None
    :param boolean verify: optional, производить ли верификацию
        ssl-сертификата при запросае
    :return: dict на основе JSON-ответа
    :rtype: dict
    :raises HttpError: если выбрасыватеся исключение requests.HTTPError
    :raises IncorrectJsonError: если JSON-ответ не может быть
        корректно прочитан
    """
    try:
        response = requests.request(
            method, url, headers=headers, data=data, verify=verify)
        response.raise_for_status()
        return json.loads(response.content)
    except requests.HTTPError as e:
        raise HttpError(e)
    except ValueError as e:
        raise IncorrectJsonError(e)


def smime_sign(certificate_file, private_key_file, data, backend='m2crypto'):
    """
    Подписывает данные в формате SMIME с использование sha256.
    В качестве бэкенда используется либо вызов openssl, либо
    библиотека M2Crypto

    :param str certificate_file: путь к сертификату
    :param str private_key_file: путь к приватному ключу
    :param str data: подписываемые данные
    :param str backend: (optional) бэкенд, используемый
        для подписи (m2crypto|openssl)
    :raises CryptoBackendError: если неверно указан backend
    :return: открепленная подпись
    :rtype: str
    """
    if backend == 'm2crypto' or backend is None:
        from M2Crypto import SMIME, BIO

        if not isinstance(data, bytes):
            data = bytes(data)

        signer = SMIME.SMIME()
        signer.load_key(private_key_file, certificate_file)
        p7 = signer.sign(
            BIO.MemoryBuffer(data), flags=SMIME.PKCS7_DETACHED, algo='sha256')
        signed_message = BIO.MemoryBuffer()
        p7.write_der(signed_message)
        return signed_message.read()
    elif backend == 'openssl':
        source_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
        source_file.write(data)
        source_file.close()
        source_path = source_file.name

        destination_file = tempfile.NamedTemporaryFile(mode='wb', delete=False)
        destination_file.close()
        destination_path = destination_file.name

        cmd = (
            'openssl smime -sign -md sha256 -in {f_in} -signer {cert} -inkey '
            '{key} -out {f_out} -outform DER')
        os.system(cmd.format(
            f_in=source_path,
            cert=certificate_file,
            key=private_key_file,
            f_out=destination_path,
        ))

        signed_message = open(destination_path, 'rb').read()
        os.unlink(source_path)
        os.unlink(destination_path)
        return signed_message
    else:
        raise CryptoBackendError(
            'Unknown cryptography backend. Use openssl or m2crypto value.')


def csp_sign(thumbprint, password, data):
    """
    Подписывает данные с использованием ГОСТ Р 34.10-2012 открепленной подписи.
    В качестве бэкенда используется утилита cryptcp из ПО КриптоПРО CSP.

    :param str thumbprint: SHA1 отпечаток сертификата, связанного
        с зкарытым ключем
    :param str password: пароль для контейнера закрытого ключа
    :param str data: подписываемые данные
    """
    tmp_dir = tempfile.gettempdir()
    source_file = tempfile.NamedTemporaryFile(
        mode='w', delete=False, dir=tmp_dir)
    source_file.write(data)
    source_file.close()
    source_path = source_file.name
    destination_path = source_path + '.sgn'

    cmd = (
        "cryptcp -signf -norev -dir {tmp_dir} -der -strict -cert -detached "
        "-thumbprint {thumbprint} -pin '{password}' {f_in} 2>&1 >/dev/null")
    os.system(cmd.format(
        tmp_dir=tmp_dir,
        thumbprint=thumbprint,
        password=password,
        f_in=source_path
    ))

    signed_message = open(destination_path, 'rb').read()
    os.unlink(source_path)
    os.unlink(destination_path)
    return signed_message


def sign_params(params, settings, backend='csp'):
    """
    Подписывает параметры запроса и добавляет в params ключ client_secret.
    Подпись основывается на полях: `scope`, `timestamp`, `client_id`, `state`.

    :param dict params: параметры запроса
    :param EsiaSettings settings: настройки модуля ЕСИА
    :param str backend: (optional) бэкенд используемый
        для подписи (m2crypto|openssl|csp)
    :raises CryptoBackendError: если неверно указан backend
    :return: подписанные параметры запроса
    :rtype: dict
    """
    plaintext = params.get('scope', '') + params.get('timestamp', '') + \
        params.get('client_id', '') + params.get('state', '')
    if backend == 'csp':
        raw_client_secret = csp_sign(
            settings.csp_cert_thumbprint,
            settings.csp_container_pwd, plaintext)
    else:
        raw_client_secret = smime_sign(
            settings.certificate_file, settings.private_key_file,
            plaintext, backend)
    params.update(
        client_secret=base64.urlsafe_b64encode(
            raw_client_secret).decode('utf-8'),
    )
    return params


def get_timestamp():
    """
    Возвращает текущую дату и время в строковом представлении с указанем зоны
    в формате пригодном для использования при взаимодействии с ЕСИА

    :return: текущая дата и время
    :rtype: str
    """
    return datetime.datetime.now(pytz.utc).\
        strftime('%Y.%m.%d %H:%M:%S %z').strip()
