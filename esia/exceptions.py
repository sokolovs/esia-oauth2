# -*- coding: utf-8 -*-
# Код основан на пакете esia-connector
# https://github.com/eigenmethod/esia-connector
# Лицензия: https://github.com/eigenmethod/esia-connector/blob/master/LICENSE.txt
# Copyright (c) 2015, Septem Capital
import jwt
import requests.exceptions


class EsiaError(Exception):
    pass


class IncorrectJsonError(EsiaError, ValueError):
    pass


class IncorrectMarkerError(EsiaError, jwt.InvalidTokenError):
    pass


class HttpError(EsiaError, requests.exceptions.HTTPError):
    pass


class SignBackendError(Exception):
    pass


class ConfigFileError(Exception):
    pass
