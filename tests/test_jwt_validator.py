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
from jwkest.jwk import KEYS, SYMKey
from jwkest.jws import JWS
from flask_of_oil.jwt_validator import JwtValidator
from tests.utils import get_valid_expiration, get_invalid_expiration


class MockResponse:
    status_code = 200

    def __init__(self, method, url, **kwargs):
        pass

    jwks = {"keys": [
        {
            "use": "sig",
            "alg": "RS256",
            "n": "sPgvDZDGhsyQS6_8pY_v8lKrf4lca3WQgAsUil9ZqO6E5sy8L7xmyhzuCzHqGHAy3x_dkP_7sC7whJ744cbs7EKM3g9eK3FNnUOVf2q8JFN-8060P_R6iYZX8gLh_FRqHmHWsl7yxUJcHuJgSp30USHRStHzddexDRavc8g8J7CBsYPcLBhJIcF_kEWPVC6ovJUpU-xCvlYh3PmeCIObqn8cDkBctJNLLSYAoh9bkWDk4SEMU4ib--n6t3gD9sPkiE5stQJdajnG5AR3w756L-zArBmjiqVTN9vZH0VhooaaB4iD24lTnLt9rWddSalMGtjQBg6qnU2wKlMZmWWAGn-x2EAPS8_Rpi0Zx1Cue7uLhleaPTzHeNSuvmfLLC08Psq7f4_e306CSa8A3Ps6-UtU54OHbg8kO10BbJ_ug-9FSa1p9G3H021-IS1a5AnZN45tf6b3DmPG7chhlafENWuQQ30JR4Jolzz5F3vtqrxFUSHC55DTxLmHNrownSDPCsjLu7hbVWaXGxJLKvYE0F1kFlhh3JcGLwRfCAJj_-Z0rLRpfq5eA_jmqtT_KlMikuBadi0-T3U1ygijUL332kwSdYVw0hg8CspyXtOc0RBCL0cKFBw-zkXJMCZiKWCxgwprR2ej_mFGOFewYM-voNybpNKOzLO8oqR-G1-MXik",
            "kty": "RSA",
            "e": "AQAB",
            "kid": "123456"
        }
    ]}

    text = json.dumps(jwks)


@pytest.fixture()
def jwks_mock(monkeypatch):
    monkeypatch.setattr("flask_of_oil.jwt_validator.request", MockResponse)






class TestJwtValidator:
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
      "qi": "Ca_jyNDZeqhMhBMEdUtAz4pnKUgYSMHfhgR-tEMyq4mHD_KOYxsPo1cRcZFCPtNsodVSVY98CmQHCViBuqUt_JbYzUPvH80lHWU6_vD_cXz9nNki6g8_RytDfDO043x_p43MInBqXvcM-u4jJBjcDtowPVTd77hU8R7hr9YYbg7jQbfvKcwGsKf6zc3u3VfwWh9S5OD6-d8WzVHIj7BSafrNe0rCXGzc8qcbH_Ju59IeHNKjvWN7Z39E0trJzfwaxeGP4EKqW93TjIoCG9y_V5ktMsMjNghCHPDgtkIyvV2dLKMbYu9zeTrTvoIyb_C4chDW6wUziDWA7gYytHVugA"
    }]})

    private_key_jwks = KEYS().load_jwks(private_key_jwks_data)

    def test_invalid_jwt(self, jwks_mock):
        validator = JwtValidator("http://localhost/", "", "")
        result = validator.validate("abcdef")
        assert not result["active"]

    def test_invalid_jwt_format(self, jwks_mock):
        validator = JwtValidator("http://localhost/", "", "")
        result = validator.validate("abcdef.abcdef.abcdef")
        assert not result["active"]

    def test_invalid_signature(self, jwks_mock):
        jws = JWS({"sub": "me", "iss": "", "aud": "", "exp": get_valid_expiration()}, alg="RS256")
        signed_token = jws.sign_compact(keys=self.private_key_jwks)
        invalid_token = signed_token[:-1]
        validator = JwtValidator("http://localhost/", "", "")
        result = validator.validate(invalid_token)
        assert not result["active"]

    def test_invalid_issuer(self, jwks_mock):
        jws = JWS({"sub": "me", "iss": "https://attacker.example.com", "aud": "", "exp": get_valid_expiration()}, alg="RS256")
        signed_token = jws.sign_compact(keys=self.private_key_jwks)
        validator = JwtValidator("http://localhost/", "https://legit.example.com", "")
        result = validator.validate(signed_token)
        assert not result["active"]

    def test_missing_audience(self, jwks_mock):
        jws = JWS({"sub": "me", "iss": "", "exp": get_valid_expiration()}, alg="RS256")
        signed_token = jws.sign_compact(keys=self.private_key_jwks)
        validator = JwtValidator("http://localhost/", "", "")
        result = validator.validate(signed_token)
        assert not result["active"]

    def test_invalid_audience(self, jwks_mock):
        jws = JWS({"sub": "me", "iss": "", "aud": "other-audience", "exp": get_valid_expiration()}, alg="RS256")
        signed_token = jws.sign_compact(keys=self.private_key_jwks)
        validator = JwtValidator("http://localhost/", issuer="", audience="legitimate-audience")
        result = validator.validate(signed_token)
        assert not result["active"]

    def test_invalid_signing_algorithm(self, jwks_mock):
        key = SYMKey(key="Secr3t", alg="HS256")
        jws = JWS({"sub": "me", "iss": "", "aud": "", "exp": get_valid_expiration()}, alg="HS256")
        signed_token = jws.sign_compact(keys=[key])
        validator = JwtValidator("http://localhost/", "", "")
        result = validator.validate(signed_token)
        assert not result["active"]

    def test_expiration_missing(self, jwks_mock):
        jws = JWS({"sub": "me", "iss": "", "aud": ""}, alg="RS256")
        signed_token = jws.sign_compact(keys=self.private_key_jwks)
        validator = JwtValidator("http://localhost/", issuer="", audience="")
        result = validator.validate(signed_token)
        assert not result["active"]

    def test_subject_missing(self, jwks_mock):
        jws = JWS({"iss": "", "aud": "", "exp": get_valid_expiration()}, alg="RS256")
        signed_token = jws.sign_compact(keys=self.private_key_jwks)
        validator = JwtValidator("http://localhost/", issuer="", audience="")
        result = validator.validate(signed_token)
        assert not result["active"]

    def test_set_default_scope_value(self, jwks_mock):
        jws = JWS({"sub": "me", "iss": "", "aud": "", "exp": get_valid_expiration()}, alg="RS256")
        signed_token = jws.sign_compact(keys=self.private_key_jwks)
        validator = JwtValidator("http://localhost/", issuer="", audience="")
        result = validator.validate(signed_token)
        assert result["scope"] == ""

    def test_expired_token(self, jwks_mock):
        jws = JWS({"sub": "me", "iss": "", "aud": "", "exp": get_invalid_expiration()}, alg="RS256")
        signed_token = jws.sign_compact(keys=self.private_key_jwks)
        validator = JwtValidator("http://localhost/", issuer="", audience="")
        result = validator.validate(signed_token)
        assert not result["active"]

    def test_valid_jwt(self, jwks_mock):

        jws = JWS({"sub": "me", "iss": "", "aud": "", "exp": get_valid_expiration()}, alg="RS256")
        signed_token = jws.sign_compact(keys=self.private_key_jwks)
        validator = JwtValidator("http://localhost/", "", "")
        result = validator.validate(signed_token)
        assert result["active"]
