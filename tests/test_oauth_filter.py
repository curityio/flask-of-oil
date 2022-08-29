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
from flask import Flask, request
from jwkest.jwk import KEYS
from jwkest.jws import JWS

from flask_of_oil import OAuthFilter
from tests.utils import get_valid_expiration


class MultipleIssuersRequestMock:
    status_code = 200

    def __init__(self, method, url, **kwargs):
        if url == "https://issuer1.example.com/jwks":
            self.text = json.dumps({"keys": [
                {
                    "use": "sig",
                    "alg": "RS256",
                    "n": "sPgvDZDGhsyQS6_8pY_v8lKrf4lca3WQgAsUil9ZqO6E5sy8L7xmyhzuCzHqGHAy3x_dkP_7sC7whJ744cbs7EKM3g9eK3FNnUOVf2q8JFN-8060P_R6iYZX8gLh_FRqHmHWsl7yxUJcHuJgSp30USHRStHzddexDRavc8g8J7CBsYPcLBhJIcF_kEWPVC6ovJUpU-xCvlYh3PmeCIObqn8cDkBctJNLLSYAoh9bkWDk4SEMU4ib--n6t3gD9sPkiE5stQJdajnG5AR3w756L-zArBmjiqVTN9vZH0VhooaaB4iD24lTnLt9rWddSalMGtjQBg6qnU2wKlMZmWWAGn-x2EAPS8_Rpi0Zx1Cue7uLhleaPTzHeNSuvmfLLC08Psq7f4_e306CSa8A3Ps6-UtU54OHbg8kO10BbJ_ug-9FSa1p9G3H021-IS1a5AnZN45tf6b3DmPG7chhlafENWuQQ30JR4Jolzz5F3vtqrxFUSHC55DTxLmHNrownSDPCsjLu7hbVWaXGxJLKvYE0F1kFlhh3JcGLwRfCAJj_-Z0rLRpfq5eA_jmqtT_KlMikuBadi0-T3U1ygijUL332kwSdYVw0hg8CspyXtOc0RBCL0cKFBw-zkXJMCZiKWCxgwprR2ej_mFGOFewYM-voNybpNKOzLO8oqR-G1-MXik",
                    "kty": "RSA",
                    "e": "AQAB",
                    "kid": "1"
                }
            ]})
        else:
            self.text = json.dumps({"keys": [
                {
                    "use": "sig",
                    "alg": "RS256",
                    "n": " wuD2lYi0dAlX9QlhmnlUbeb-uFxTB0-q2HhpIaAer0KO3oRBauV56XhUhiYEtX8Q73R1j0qz72kJuv16DMXoawODm0s5scETP9dYPrh6xq0FxdtSVYnhFCLZyM369_FaAmoi7rhUW1PD4Ib2kZKYtwknntVCS1vA8_9eIMEyJzi5HALXlnTrwaQNNRifdVku8KCw2iTDpcEn3nCoyL6cU4vt1hSaum05n3dPwrdaRxsQPwYYw34A1SxoTjKP8bplCphk2_Iov-1-u73KRE9WWnXHPMia3W7-krVmI9sVJMElgvdZb509Q0jtHerJt6fyxDGusFVZ_cQdviZYkWYEECtlp0_Z6qRm_1czyx78G2-qNGs8V7mdFDBkN1wW8z7IRB5VMojqAGOne9KNJQPzd5kHwFQ2V94hbzi-IUrq4CLQW82wbWzvL9s2ULa7-hOJodg4RyQafh2PDjK7SGktBEBbR6B0XJPsDpf19MyX9iTD7bxUYb3UZsaqdqTlmnkQVMEtB9TJl_VHtG_eId-7a2WzKkIqQWCUIJxeEIevBuj3dd1UBmkME2mS2y5ZVkmFjaJVSfihPKS3XoByu73IEqQsUXCMe8HUbV4591QYLevDj31hFGa8hh3kA3AbT_yGuz8IO9nweq988Vc8qvjtM6IH-6l6UEVQd1OuRTkQ9mk",
                    "kty": "RSA",
                    "e": "AQAB",
                    "kid": "2"
                }
            ]})
        pass


@pytest.fixture()
def multiple_issuers_mock(monkeypatch):
    monkeypatch.setattr("flask_of_oil.jwt_validator.request", MultipleIssuersRequestMock)


class ValidIntrospectionMockResponse:
    def __init__(self, method, url, **kwargs):
        if url == "http://localhost/introspect":
            if kwargs["data"] and kwargs["data"]["token"] and kwargs["data"]["token"] == "valid_token":
                self.status_code = 200
                self.text = json.dumps({
                    "sub": "me",
                    "aud": "legitimate-audience",
                    "iss": "https://legitimate.example.com",
                    "exp": get_valid_expiration(),
                    "scope": "read",
                    "my_data": "abc",
                    "active": True
                })
            else:
                self.status_code = 204
        pass

    headers = {
        "Content-Type": "application/json"
    }


class InsufficientScopeIntrospectionMockResponse:
    def __init__(self, method, url, **kwargs):
        if url == "http://localhost/introspect":
            self.status_code = 200
            self.text = json.dumps({
                "sub": "me",
                "aud": "legitimate-audience",
                "iss": "https://legitimate.example.com",
                "exp": get_valid_expiration(),
                "scope": "write",
                "my_data": "abc",
                "active": True
            })
        pass

    headers = {
        "Content-Type": "application/json"
    }


class MissingClaimIntrospectionMockResponse:
    def __init__(self, method, url, **kwargs):
        if url == "http://localhost/introspect":
            self.status_code = 200
            self.text = json.dumps({
                "sub": "me",
                "aud": "legitimate-audience",
                "iss": "https://legitimate.example.com",
                "exp": get_valid_expiration(),
                "scope": "read",
                "active": True
            })
        pass

    headers = {
        "Content-Type": "application/json"
    }


@pytest.fixture()
def valid_introspection_mock(monkeypatch):
    monkeypatch.setattr("flask_of_oil.opaque_validator.request", ValidIntrospectionMockResponse)


@pytest.fixture()
def insufficient_scope_introspection_mock(monkeypatch):
    monkeypatch.setattr("flask_of_oil.opaque_validator.request", InsufficientScopeIntrospectionMockResponse)


@pytest.fixture()
def missing_claim_introspection_mock(monkeypatch):
    monkeypatch.setattr("flask_of_oil.opaque_validator.request", MissingClaimIntrospectionMockResponse)


def configure_app():
    _app = Flask("Test")
    _oauth = OAuthFilter(verify_ssl=True)
    _oauth.configure_with_opaque("http://localhost/introspect", "client1", "Secr3t")

    @_app.route("/protected")
    @_oauth.protect(scopes="read", claims={"my_data": "abc"})
    def protected_route():
        return "OK"

    return _app


@pytest.fixture()
def app_with_multiple_issuers(multiple_issuers_mock):
    _app = Flask("Test")
    _oauth = OAuthFilter(verify_ssl=True)
    _oauth.configure_with_multiple_jwt_issuers(["https://issuer1.example.com", "https://issuer2.example.com"], "legitimate-audience")

    @_app.route("/protected")
    @_oauth.protect()
    def protected_route():
        return request.claims["iss"]

    yield _app


@pytest.fixture()
def valid_introspection_app(valid_introspection_mock):
    yield configure_app()


@pytest.fixture()
def insufficient_scope_app(insufficient_scope_introspection_mock):
    yield configure_app()


@pytest.fixture()
def missing_claim_app(missing_claim_introspection_mock):
    yield configure_app()


@pytest.fixture()
def test_client(valid_introspection_app):
    return valid_introspection_app.test_client()


class TestOAuthFilter:
    def test_request_without_token_should_return_401(self, test_client):
        result = test_client.get("/protected")
        assert result.status_code == 401

    def test_request_with_invalid_token_should_return_401(self, test_client):
        result = test_client.get("/protected", headers={"Authorization": "Bearer invalid_token"})
        assert result.status_code == 401

    def test_request_with_valid_token(self, test_client):
        result = test_client.get("/protected", headers={"Authorization": "Bearer valid_token"})
        assert result.status_code == 200

    def test_request_with_insufficient_claims(self, insufficient_scope_app):
        result = insufficient_scope_app.test_client().get("/protected", headers={"Authorization": "Bearer insufficient_scope_token"})
        assert result.status_code == 403

    def test_request_with_missing_claims(self, missing_claim_app):
        result = missing_claim_app.test_client().get("/protected", headers={"Authorization": "Bearer missing_claim_token"})
        assert result.status_code == 403

    def test_valid_request_when_multiple_issuers_configured(self, app_with_multiple_issuers):
        private_key_jwks_data = json.dumps({"keys": [{
            "alg": "RS256",
            "d": "Bx-5ufpFzTyQ40S09Yk8zh_YoLkYpYhfBiu40PUtRWkMpCnbukqdExSYQVuDollp6T3kJaeLkmt66fibgwmgYfmWQbfGp6_XWwK5Rh7RO6xTMPVn7I2P6gqLCCzOu64-QCjaHRlIMC6pFkkwoFa8p6nZcTSdPPVicc9wkq2d1k8ueV6zta0bzIyrvbs_HZ_Sa30DSkossAxrL1t3d1cTV7xNydKt2-SnoxKjj3zJqw_s4GJiZHGpLdPpo6Pkk1t0m-DkUvxCyTlRy1eh5pkiKNztlXMwXsijxMNIRnaWWC-PWPxJRCr1pbQnRzXtzthOcWPTw_RB_ZqyAivENqU1kEpQH60jbwkYiPTV_on1qjVqPBjB0LMTfRdKd2LGaDX72D71aLr1syVJAF43tDyLQ4LizXU_oC4ynDaz7zFle96L8dPGYLbblI9Ea3pqAEpy5dt6Yf3cZ9yqmwN0-_0rfPw7HX_pvUoFJ4m7R_ak60tBium_L1EWzS2GuDc24NP2oMnS-f9sEPA51ND_8LJ-quWOMPzSCdcL3pz5g1zNJZcKL-D90E_jRP2-PXta2XBNCfA2aOHfwJC33ZJcYKrPPX4CdwB4YdnRQo0ORWN9lQIQlQosG0kfYswNUZ5DMz-6V9Xq3UaWdaTDD4oyTSiS6BjD5o-sHUQfTR4-BSKcO3E",
            "dp": "qg349mlhUcptz302PUYc0mvE_gPO_deW5zCn1eu9AeCR8eAxut30YBjte4jWDRXseUr9mhSfyfUpYVhT1eBMlg5kDAcv8PuFL6uIY3uAx0gkUFtd9pqj5x9b9NQjxNh27mi3EZP0_UbMsw3Y52CoaNIQRiazKH-WF7usVXU70vePlrADmz41lNxP2JHRIl9ITnm556Mpwz6H-f3YhFTKoX-ot30JoC_yY0rssacJrUIDSzgigeNW8LBOkADQ4sj-SNG-Hn_7oJIPJ_XTglrt31XJrkp9m-K7DB75uDlwWHBwidu8tzNZ4SHmmCw9zxI_7UczU2W1wjufPcJyyq2MCQ",
            "dq": "uUtZMtfpG5sA9bDFuBRKqD0QB4hERXaJ4uNO_m9bOXclGA-axihupcHENs6tUCxg8H8Tr1j7JZ1eW4KIVEF-RUK2geckwacNZ8Cjn2msJfCkeKff_9agTzlZQspB81Hc5ScVMC-zcUHucbopGGf3YqYaLvt1BjlIcwfqQH21yZ-WSdIaDg7tH9A-_PsaXkfIwQcBTXWzHhFAGRh_xgmJ-OoBJHed8mJWgNEq_uvzC4zD3fph2f4XGK3plhITXFpY-f8wn3jL_pN26axzzd38mn8cabN2nr4OWLWn5Fi4Gtj0jPI8qZ4Lwr__HqUW9uMc46KpXAydBur5kH-f8sWIxQ",
            "e": "AQAB",
            "ext": "true",
            "key_ops": ["sign"],
            "kty": "RSA",
            "n": "sPgvDZDGhsyQS6_8pY_v8lKrf4lca3WQgAsUil9ZqO6E5sy8L7xmyhzuCzHqGHAy3x_dkP_7sC7whJ744cbs7EKM3g9eK3FNnUOVf2q8JFN-8060P_R6iYZX8gLh_FRqHmHWsl7yxUJcHuJgSp30USHRStHzddexDRavc8g8J7CBsYPcLBhJIcF_kEWPVC6ovJUpU-xCvlYh3PmeCIObqn8cDkBctJNLLSYAoh9bkWDk4SEMU4ib--n6t3gD9sPkiE5stQJdajnG5AR3w756L-zArBmjiqVTN9vZH0VhooaaB4iD24lTnLt9rWddSalMGtjQBg6qnU2wKlMZmWWAGn-x2EAPS8_Rpi0Zx1Cue7uLhleaPTzHeNSuvmfLLC08Psq7f4_e306CSa8A3Ps6-UtU54OHbg8kO10BbJ_ug-9FSa1p9G3H021-IS1a5AnZN45tf6b3DmPG7chhlafENWuQQ30JR4Jolzz5F3vtqrxFUSHC55DTxLmHNrownSDPCsjLu7hbVWaXGxJLKvYE0F1kFlhh3JcGLwRfCAJj_-Z0rLRpfq5eA_jmqtT_KlMikuBadi0-T3U1ygijUL332kwSdYVw0hg8CspyXtOc0RBCL0cKFBw-zkXJMCZiKWCxgwprR2ej_mFGOFewYM-voNybpNKOzLO8oqR-G1-MXik",
            "p": "6N-nWxZY64LpxLnhvLAl9eHvQYgOTUFyEdIvQe5y84t-kD8CzwK-033EZDZ7-3w0gM4LLL3XRk3AdyVEv5uI2tFgli3J44ojNusVyYYKZGtYQMmMGuCdJXNrUNkCAX-_VVasykHUa_Hjh--Lt0KComRrlVqL_m5rpI9sBuXp5fp40UHGWn7-UL1XsuU7Md34591h3WLOcpSd6PG1s34d7Lvf0J2oBgrRrtQE5yV4_SRS4DDblUMX9CRpvmp-7DUctplYDyN_aMGYYwzeAy4Dwat3o8KR2iazZ5TKlDs6ms8PeKrzktWxpetD5FPzGBqGxl0Oo3RUN4Kfpc0DyFPpJQ",
            "q": "wotHOd4_PxjgQW3fVV2-aGgja5ZrFskP3XkSEI3Gyrb_QzvLaeS2ymDzraTILql5Q2csmiRBqZLiP-Af-_jPBcyLrCVQteDmpUtXHQu5NkQZBcWTxMHBxraYSz8dvGdNLzE2JRpbVlkNSEcTrxRtWSlnpT1Egku-URT3ZseUxqJZXt23usaqi_I7RGM6xYN-B1LfvOaJwf_zkygzA0HzgF796hg3D__4iEoIp2O8jt45b595TWB10FLi0ev74D9YGVRgToTVzOOKL5RPGMQlKKEXDEIHxtUPm69fiX6kblvnsivEJ6lOfu4-1TBIGUWVeIDUmZ89t3_QvF0yd3k7tQ",
            "qi": "Ca_jyNDZeqhMhBMEdUtAz4pnKUgYSMHfhgR-tEMyq4mHD_KOYxsPo1cRcZFCPtNsodVSVY98CmQHCViBuqUt_JbYzUPvH80lHWU6_vD_cXz9nNki6g8_RytDfDO043x_p43MInBqXvcM-u4jJBjcDtowPVTd77hU8R7hr9YYbg7jQbfvKcwGsKf6zc3u3VfwWh9S5OD6-d8WzVHIj7BSafrNe0rCXGzc8qcbH_Ju59IeHNKjvWN7Z39E0trJzfwaxeGP4EKqW93TjIoCG9y_V5ktMsMjNghCHPDgtkIyvV2dLKMbYu9zeTrTvoIyb_C4chDW6wUziDWA7gYytHVugA",
            "kid": "1"
        }]})

        private_key_jwks = KEYS().load_jwks(private_key_jwks_data)
        jws = JWS({
            "sub": "me",
            "iss": "https://issuer1.example.com",
            "aud": "legitimate-audience",
            "exp": get_valid_expiration()
        }, alg="RS256")
        signed_token = jws.sign_compact(keys=private_key_jwks)

        response = app_with_multiple_issuers.test_client().get("/protected", headers={"Authorization": "Bearer " + signed_token})
        assert response.status_code == 200
        assert response.data == b"https://issuer1.example.com"
