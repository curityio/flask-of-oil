##########################################################################
# Copyright 2016 Curity AB
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

import calendar
import json
import logging
import ssl
from datetime import datetime

from jwkest.jwk import KEYS
from jwkest.jws import JWS
from requests import request

from flask_of_oil.tools import base64_urldecode


class JwtValidatorException(Exception):
    pass


class JwtValidator:
    def __init__(self, jwks_url, issuer, audience, verify_ssl_server=True):
        self.supported_algorithms = ['RS256', "RS512"]
        self.jwks_url = jwks_url
        self.aud = audience
        self.iss = issuer
        self.verify_ssl_server = verify_ssl_server
        self.jwks = self.load_keys()
        self.logger = logging.getLogger(__name__)

    def validate(self, jwt):
        parts = jwt.split('.')
        if len(parts) != 3:
            self.logger.debug('Invalid JWT. Only JWS supported.')
            return {"active": False}
        # noinspection PyBroadException
        try:
            header = json.loads(base64_urldecode(parts[0]))
            payload = json.loads(base64_urldecode(parts[1]))
        except Exception:
            self.logger.debug("Invalid JWT, format not json")
            return {"active": False}

        if self.iss != payload['iss']:
            self.logger.debug("Invalid issuer %s, expected %s" % (payload['iss'], self.iss))
            return {"active": False}

        if 'aud' not in payload:
            self.logger.debug("Invalid audience, no audience in payload")
            return {"active": False}

        aud = payload['aud']

        if self.aud not in aud:
            self.logger.debug("Invalid audience %s, expected %s" % (aud, self.aud))
            return {"active": False}

        if 'alg' not in header:
            self.logger.debug("Missing algorithm in header")
            return {"active": False}

        if header['alg'] not in self.supported_algorithms:
            self.logger.debug("Unsupported algorithm in header %s" % (header['alg']))
            return {"active": False}

        jws = JWS(alg=header['alg'])

        # noinspection PyBroadException
        try:
            jws.verify_compact(jwt, self.jwks)
        except Exception:
            self.logger.debug("Exception validating signature")
            return {'active': False}

        self.logger.debug("Successfully validated signature.")

        if 'exp' not in payload:
            self.logger.debug("No expiration in body, invalid token")
            return {"active": False}

        if 'sub' not in payload:
            self.logger.debug("No subject in body, invalid token")
            return {"active": False}

        # Could be an empty scope, which may be allowed, so replace with empty string if not found
        if 'scope' not in payload:
            scope = ""
        else:
            scope = payload['scope']

        exp = payload['exp']

        d = datetime.utcnow()
        now = calendar.timegm(d.utctimetuple())

        if now >= exp:
            return {"active": False}
        else:
            return payload

    def get_jwks_data(self):
        ctx = ssl.create_default_context()
        if not self.verify_ssl_server:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        req = request("GET",
                      self.jwks_url,
                      allow_redirects=False,
                      verify=ctx.check_hostname,
                      headers={'Accept': "application/json"})

        if req.status_code == 200:
            return req.text
        else:
            raise Exception("HTTP Get error: %s" % req.status_code)

    def load_keys(self):
        # load the jwk set.
        jwks = KEYS()
        jwks.load_jwks(self.get_jwks_data())
        return jwks
