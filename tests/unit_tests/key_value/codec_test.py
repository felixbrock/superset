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
import pickle
from contextlib import nullcontext
from typing import Any

import pytest
from marshmallow import Schema

from superset.dashboards.permalink.schemas import DashboardPermalinkSchema
from superset.key_value.exceptions import (
    KeyValueCodecDecodeException,
    KeyValueCodecEncodeException,
)
from superset.key_value.types import (
    JsonKeyValueCodec,
    MarshmallowKeyValueCodec,
    PickleKeyValueCodec,
)


@pytest.mark.parametrize(
    "input_,expected_result",
    [
        (
            {"foo": "bar"},
            {"foo": "bar"},
        ),
        (
            {"foo": (1, 2, 3)},
            {"foo": [1, 2, 3]},
        ),
        (
            {1, 2, 3},
            KeyValueCodecEncodeException(),
        ),
        (
            object(),
            KeyValueCodecEncodeException(),
        ),
    ],
)
def test_json_codec(input_: Any, expected_result: Any):
    cm = (
        pytest.raises(type(expected_result))
        if isinstance(expected_result, Exception)
        else nullcontext()
    )
    with cm:
        codec = JsonKeyValueCodec()
        encoded_value = codec.encode(input_)
        assert expected_result == codec.decode(encoded_value)


@pytest.mark.parametrize(
    "schema,input_,expected_result",
    [
        (
            DashboardPermalinkSchema(),
            {
                "dashboardId": "1",
                "state": {
                    "urlParams": [["foo", "bar"], ["foo", "baz"]],
                },
            },
            {
                "dashboardId": "1",
                "state": {
                    "urlParams": [("foo", "bar"), ("foo", "baz")],
                },
            },
        ),
        (
            DashboardPermalinkSchema(),
            {"foo": "bar"},
            KeyValueCodecEncodeException(),
        ),
    ],
)
def test_marshmallow_codec(schema: Schema, input_: Any, expected_result: Any):
    cm = (
        pytest.raises(type(expected_result))
        if isinstance(expected_result, Exception)
        else nullcontext()
    )
    with cm:
        codec = MarshmallowKeyValueCodec(schema)
        encoded_value = codec.encode(input_)
        assert expected_result == codec.decode(encoded_value)


@pytest.mark.parametrize(
    "input_,expected_result",
    [
        (
            {1, 2, 3},
            {1, 2, 3},
        ),
        (
            {"foo": 1, "bar": {1: (1, 2, 3)}, "baz": {1, 2, 3}},
            {
                "foo": 1,
                "bar": {1: (1, 2, 3)},
                "baz": {1, 2, 3},
            },
        ),
    ],
)
def test_pickle_codec(input_: Any, expected_result: Any):
    codec = PickleKeyValueCodec()
    encoded_value = codec.encode(input_)
    assert expected_result == codec.decode(encoded_value)


_side_effects: list[str] = []


class _MaliciousPayload:
    """A payload whose ``__reduce__`` triggers a sentinel side effect on load."""

    def __reduce__(self) -> Any:
        return (_side_effects.append, ("pwned",))


def test_pickle_codec_rejects_unsigned_payload():
    """
    Bytes that were not produced by ``PickleKeyValueCodec.encode`` (i.e. do not
    carry a valid signature) must be rejected before ``pickle.loads`` runs, so a
    malicious ``__reduce__`` cannot execute arbitrary code.
    """
    codec = PickleKeyValueCodec()
    malicious_bytes = pickle.dumps(_MaliciousPayload())

    _side_effects.clear()
    with pytest.raises(KeyValueCodecDecodeException):
        codec.decode(malicious_bytes)
    assert _side_effects == []


def test_pickle_codec_rejects_tampered_payload():
    """A payload signed with a different key must fail signature verification."""
    codec = PickleKeyValueCodec()
    forged = PickleKeyValueCodec(secret_key="attacker-key").encode(  # noqa: S106
        _MaliciousPayload()
    )

    _side_effects.clear()
    with pytest.raises(KeyValueCodecDecodeException):
        codec.decode(forged)
    assert _side_effects == []


def test_pickle_codec_round_trip_is_signed():
    """A value encoded with the configured key round-trips successfully."""
    codec = PickleKeyValueCodec()
    value = {"foo": 1, "bar": {1: (1, 2, 3)}, "baz": {1, 2, 3}}
    encoded = codec.encode(value)
    assert encoded != pickle.dumps(value)
    assert codec.decode(encoded) == value
