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

import json
import ssl
import calendar

from datetime import datetime
from requests import request
from werkzeug.contrib.cache import SimpleCache


class OpaqueValidatorException(Exception):
    pass


class OpaqueValidator:
    def __init__(self, introspection_url, client_id, client_secret, verify_ssl_server=True):
        self.ctx = ssl.create_default_context()

        if not verify_ssl_server:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

        self._introspection_url = introspection_url
        self._client_id = client_id
        self._client_secret = client_secret

        self._token_cache = SimpleCache()

    def introspect_token(self, token):

        params = {
            'client_id': self._client_id,
            'token': token
        }

        headers = {'content-type': 'application/x-www-form-urlencoded'}

        req = request("POST",
                      self._introspection_url,
                      allow_redirects=False,
                      auth=(self._client_id, self._client_secret),
                      verify=self.ctx.check_hostname,
                      data=params,
                      headers=headers)

        if req.status_code == 200:
            return json.loads(req.text)
        else:
            raise Exception("HTTP POST error from introspection: %s" % req.status_code)

    def validate(self, token):

        d = datetime.utcnow()
        now = calendar.timegm(d.utctimetuple())

        # Lookup in cache:
        cached_response = self._token_cache.get(token)
        if cached_response is not None \
            and cached_response['active'] \
                and cached_response['exp'] >= now:

            return {"subject": cached_response['sub'],
                    "scope": cached_response['scope'],
                    "active": True}

        introspect_response = self.introspect_token(token)

        if 'active' not in introspect_response:
            raise OpaqueValidatorException("No active field in introspection response")

        if not introspect_response['active']:
            return {"active": False}

        if 'sub' not in introspect_response:
            raise OpaqueValidatorException("Missing sub field in introspection response")

        if 'exp' not in introspect_response:
            raise OpaqueValidatorException("Missing exp field in introspection response")

        if 'scope' not in introspect_response:
            raise OpaqueValidatorException("Missing scope field in introspection response")

        cache_timeout = introspect_response['exp'] - now
        self._token_cache.set(token, introspect_response, timeout=cache_timeout)

        return {"subject": introspect_response['sub'],
                "scope": introspect_response['scope'],
                "active": True}
