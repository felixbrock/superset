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
    """
    Codec that serializes values with ``pickle``.

    Because ``pickle.loads`` executes arbitrary code while deserializing, the
    pickled payload is authenticated with an HMAC-SHA256 signature derived from
    the application's ``SECRET_KEY``. The signature is verified before the
    payload is unpickled, so bytes that were not produced by this deployment
    (e.g. a tampered or shared cache backend) are rejected with a
    ``KeyValueCodecDecodeException`` instead of being deserialized. This makes
    the codec safe to retain for values that JSON cannot represent (sets,
    tuples, ``complex``, ...) without exposing an arbitrary code execution sink.
    """

    # Prefix identifying the signed payload layout, allowing the format to be
    # evolved in the future without ambiguity.
    _SIGNATURE_PREFIX = b"pkl1:"
    _DIGEST_SIZE = hashlib.sha256().digest_size

    def __init__(self, secret_key: str | bytes | None = None) -> None:
        self._secret_key = secret_key

    def _get_key(self) -> bytes:
        secret_key = self._secret_key
        if secret_key is None:
            secret_key = current_app.config["SECRET_KEY"]
        if isinstance(secret_key, str):
            return secret_key.encode("utf-8")
        return bytes(secret_key)

    def _sign(self, payload: bytes) -> bytes:
        return hmac.new(self._get_key(), payload, hashlib.sha256).digest()

    def encode(self, value: dict[Any, Any]) -> bytes:
        payload = pickle.dumps(value)
        return self._SIGNATURE_PREFIX + self._sign(payload) + payload

    def decode(self, value: bytes) -> dict[Any, Any]:
        prefix_len = len(self._SIGNATURE_PREFIX)
        if not value.startswith(self._SIGNATURE_PREFIX):
            raise KeyValueCodecDecodeException("Missing payload signature")
        signature = value[prefix_len : prefix_len + self._DIGEST_SIZE]
        payload = value[prefix_len + self._DIGEST_SIZE :]
        if not hmac.compare_digest(signature, self._sign(payload)):
            raise KeyValueCodecDecodeException("Invalid payload signature")
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
