# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
from __future__ import annotations

import hashlib
import hmac
import json
import pickle
from abc import ABC, abstractmethod
from typing import Any, TypedDict, Union
from uuid import UUID

from flask import current_app
from marshmallow import Schema, ValidationError

from superset.key_value.exceptions import (
    KeyValueCodecDecodeException,
    KeyValueCodecEncodeException,
)
from superset.utils.backports import StrEnum

Key = Union[int, UUID]

_PICKLE_HMAC_SALT = b"superset.key_value.PickleKeyValueCodec"
_PICKLE_SIGNATURE_SIZE = hashlib.sha256().digest_size


def _get_pickle_hmac_key() -> bytes:
    """Derive a dedicated pickle signing key from the application secret."""
    secret_key = current_app.secret_key
    if not secret_key:
        raise RuntimeError("SECRET_KEY must be configured to use PickleKeyValueCodec")
    if isinstance(secret_key, str):
        secret_key = secret_key.encode()
    return hmac.digest(secret_key, _PICKLE_HMAC_SALT, hashlib.sha256)


class KeyValueFilter(TypedDict, total=False):
    resource: str
    id: int | None
    uuid: UUID | None


class KeyValueResource(StrEnum):
    APP = "app"
    DASHBOARD_PERMALINK = "dashboard_permalink"
    EXPLORE_PERMALINK = "explore_permalink"
    METASTORE_CACHE = "superset_metastore_cache"
    LOCK = "lock"
    PKCE_CODE_VERIFIER = "pkce_code_verifier"
    SQLLAB_PERMALINK = "sqllab_permalink"


class SharedKey(StrEnum):
    DASHBOARD_PERMALINK_SALT = "dashboard_permalink_salt"
    EXPLORE_PERMALINK_SALT = "explore_permalink_salt"
    SQLLAB_PERMALINK_SALT = "sqllab_permalink_salt"
    # Monotonically increasing version used to revoke outstanding guest tokens.
    # Bumping it invalidates every guest token minted with a lower version.
    GUEST_TOKEN_REVOCATION_VERSION = "guest_token_revocation_version"  # noqa: S105


class KeyValueCodec(ABC):
    @abstractmethod
    def encode(self, value: Any) -> bytes: ...

    @abstractmethod
    def decode(self, value: bytes) -> Any: ...


class JsonKeyValueCodec(KeyValueCodec):
    def encode(self, value: dict[Any, Any]) -> bytes:
        try:
            return bytes(json.dumps(value), encoding="utf-8")
        except TypeError as ex:
            raise KeyValueCodecEncodeException(str(ex)) from ex

    def decode(self, value: bytes) -> dict[Any, Any]:
        try:
            return json.loads(value)
        except TypeError as ex:
            raise KeyValueCodecDecodeException(str(ex)) from ex


class PickleKeyValueCodec(KeyValueCodec):
    def encode(self, value: dict[Any, Any]) -> bytes:
        payload = pickle.dumps(value)
        signature = hmac.digest(_get_pickle_hmac_key(), payload, hashlib.sha256)
        return signature + payload

    def decode(self, value: bytes) -> dict[Any, Any]:
        signature = value[:_PICKLE_SIGNATURE_SIZE]
        payload = value[_PICKLE_SIGNATURE_SIZE:]
        expected_signature = hmac.digest(
            _get_pickle_hmac_key(), payload, hashlib.sha256
        )
        if len(signature) != _PICKLE_SIGNATURE_SIZE or not hmac.compare_digest(
            signature, expected_signature
        ):
            raise KeyValueCodecDecodeException("Invalid pickle payload signature")
        return pickle.loads(payload)  # noqa: S301


class MarshmallowKeyValueCodec(JsonKeyValueCodec):
    def __init__(self, schema: Schema):
        self.schema = schema

    def encode(self, value: dict[Any, Any]) -> bytes:
        try:
            obj = self.schema.dump(value)
            return super().encode(obj)
        except ValidationError as ex:
            raise KeyValueCodecEncodeException(message=str(ex)) from ex

    def decode(self, value: bytes) -> dict[Any, Any]:
        try:
            obj = super().decode(value)
            return self.schema.load(obj)
        except ValidationError as ex:
            raise KeyValueCodecEncodeException(message=str(ex)) from ex
