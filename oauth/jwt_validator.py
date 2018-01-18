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
import ssl
import re
from datetime import datetime

from jwkest.jwk import KEYS
from jwkest.jws import JWS
from requests import request


from tools import base64_urldecode


class JwtValidatorException(Exception):
    pass


class JwtValidator:
    def __init__(self, jwks_url, issuer, audience, verify_ssl_server=True):
        self.supported_algoritms = ['RS256', "RS512"]
        self.jwks_url = jwks_url
        self.aud = audience
        self.iss = issuer
        self.verify_ssl_server = verify_ssl_server

        self.jwks = self.load_keys()

    def validate(self, jwt):
        parts = jwt.split('.')
        if len(parts) != 3:
            print 'Invalid JWT. Only JWS supported.'
            return {"active": False}
        try:
            header = json.loads(base64_urldecode(parts[0]))
            payload = json.loads(base64_urldecode(parts[1]))
        except Exception as e:
            print "Invalid JWT, format not json"
            return {"active": False}

        if self.iss != payload['iss']:
            print "Invalid issuer %s, expected %s" % (payload['iss'], self.iss)
            return {"active": False}

        if 'aud' not in payload:
            print "Invalid audience, no audience in payload"
            return {"active": False}

        aud = payload['aud']

        if self.aud not in aud:
            print "Invalid audience %s, expected %s" % (aud, self.aud)
            return {"active": False}

        if 'alg' not in header:
            print "Missing algorithm in header"
            return {"active": False}

        if header['alg'] not in self.supported_algoritms:
            print "Unsupported algorithm in header %s" % (header['alg'])
            return {"active": False}

        jws = JWS(alg=header['alg'])

        # Raises exception when signature is invalid
        try:
            jws.verify_compact(jwt, self.jwks)
        except Exception as e:
            print "Exception validating signature"
            return {'active': False}

        print "Successfully validated signature."

        if 'exp' not in payload:
            print "No expiration in body, invalid token"
            return {"active": False}

        if 'sub' not in payload:
            print "No subject in body, invalid token"
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
            return {
                "subject": payload['sub'],
                "scope": scope,
                "active": True
            }

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
