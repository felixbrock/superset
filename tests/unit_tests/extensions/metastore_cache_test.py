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
from uuid import uuid4

from pytest_mock import MockerFixture

from superset.extensions.metastore_cache import SupersetMetastoreCache
from superset.key_value.exceptions import KeyValueCodecDecodeException
from superset.key_value.types import PickleKeyValueCodec


def _cache() -> SupersetMetastoreCache:
    return SupersetMetastoreCache(namespace=uuid4(), codec=PickleKeyValueCodec())


def test_get_returns_none_on_decode_error(mocker: MockerFixture) -> None:
    """
    Entries that cannot be decoded (e.g. legacy unsigned pickle data written
    before payload signing, or bytes with an invalid signature) are treated as
    a cache miss instead of raising to the caller.
    """
    dao = mocker.patch("superset.daos.key_value.KeyValueDAO")
    dao.get_value.side_effect = KeyValueCodecDecodeException()

    assert _cache().get("some-key") is None


def test_get_returns_value_on_success(mocker: MockerFixture) -> None:
    dao = mocker.patch("superset.daos.key_value.KeyValueDAO")
    dao.get_value.return_value = {"foo": "bar"}

    assert _cache().get("some-key") == {"foo": "bar"}
