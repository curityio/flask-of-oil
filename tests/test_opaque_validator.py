##########################################################################
# Copyright 2022 Curity AB
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################

import json
import pytest

from flask_of_oil import OpaqueValidator, OpaqueValidatorException
from tests.utils import get_valid_expiration


class ValidIntrospectionMockResponse:
    status_code = 200

    def __init__(self, method, url, **kwargs):
        self.text = json.dumps({
            "sub": "me",
            "aud": "legitimate-audience",
            "iss": "https://legitimate.example.com",
            "exp": get_valid_expiration(),
            "scope": "",
            "active": True
        })
        pass

    headers = {
        "Content-Type": "application/json"
    }


class MissingSubMockResponse:
    status_code = 200

    def __init__(self, method, url, **kwargs):
        self.text = json.dumps({
            "aud": "legitimate-audience",
            "iss": "https://legitimate.example.com",
            "exp": get_valid_expiration(),
            "scope": "",
            "active": True
        })
        pass

    headers = {
        "Content-Type": "application/json"
    }


class MissingExpMockResponse:
    status_code = 200

    def __init__(self, method, url, **kwargs):
        self.text = json.dumps({
            "sub": "me",
            "aud": "legitimate-audience",
            "iss": "https://legitimate.example.com",
            "scope": "",
            "active": True
        })
        pass

    headers = {
        "Content-Type": "application/json"
    }


class MissingScopeMockResponse:
    status_code = 200

    def __init__(self, method, url, **kwargs):
        self.text = json.dumps({
            "sub": "me",
            "aud": "legitimate-audience",
            "iss": "https://legitimate.example.com",
            "exp": get_valid_expiration(),
            "active": True
        })
        pass

    headers = {
        "Content-Type": "application/json"
    }


class EmptyIntrospectionResponse:
    status_code = 204
    headers = {
        "Content-Type": "application/json"
    }

    def __init__(self, method, url, **kwargs):
        pass


@pytest.fixture()
def valid_introspection_mock(monkeypatch):
    monkeypatch.setattr("flask_of_oil.opaque_validator.request", ValidIntrospectionMockResponse)


@pytest.fixture()
def empty_introspection_mock(monkeypatch):
    monkeypatch.setattr("flask_of_oil.opaque_validator.request", EmptyIntrospectionResponse)


@pytest.fixture(params=["sub", "exp", "scope"])
def missing_claim_mock(request, monkeypatch):
    if request.param == "sub":
        mock_response = MissingSubMockResponse
    elif request.param == "exp":
        mock_response = MissingExpMockResponse
    else:
        mock_response = MissingScopeMockResponse

    monkeypatch.setattr("flask_of_oil.opaque_validator.request", mock_response)


class TestOpaqueValidator:
    def test_should_cache_introspection_result(self, valid_introspection_mock):
        validator = OpaqueValidator("http://localhost/introspect", "client1", "Secret")
        token = "abcdef"
        result = validator.validate(token)
        assert result["active"]
        assert not validator._token_cache.get(token) is None

    def test_should_return_false_when_no_data_from_introspection(self, empty_introspection_mock):
        validator = OpaqueValidator("http://localhost/introspect", "client1", "Secret")
        token = "abcdef"
        result = validator.validate(token)
        assert not result["active"]

    def test_should_return_active_false_when_cache_expires(self):
        payload = {
            "sub": "me",
            "active": False
        }

        validator = OpaqueValidator("http://localhost/introspect", "client1", "Secret")
        token = "abcdef"
        validator._token_cache.set(token, payload)
        result = validator.validate(token)
        assert not result["active"]

    def test_missing_claim(self, missing_claim_mock):
        validator = OpaqueValidator("http://localhost/introspect", "client1", "Secret")
        token = "abcdef"
        with pytest.raises(OpaqueValidatorException):
            validator.validate(token)

    def test_valid_token(self, valid_introspection_mock):
        validator = OpaqueValidator("http://localhost/introspect", "client1", "Secret")
        token = "abcdef"
        result = validator.validate(token)
        assert result["active"]

