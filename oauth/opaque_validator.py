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
import warnings
import jwkest.jws

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
            'token': token
        }

        headers = {'content-type': 'application/x-www-form-urlencoded',
                   'accept': 'application/jwt, application/json;q=0.9, text/plain;q=0.8, text/html;q=0.7'}

        req = request("POST",
                      self._introspection_url,
                      allow_redirects=False,
                      auth=(self._client_id, self._client_secret),
                      verify=self.ctx.check_hostname,
                      data=params,
                      headers=headers)

        response_content_type = req.headers.get("Content-Type", "text/plain").split(";")[0]
        result = {}
        cache_duration_header_value = req.headers.get("Cache-Duration", None)

        if cache_duration_header_value:
            # Turn 'public, max-age=31536000' into {'public': None, 'max-age': '31536000'}
            cache_duration_parts = dict(
                (part_values[0], None if len(part_values) == 1 else part_values[1])
                for part_values in [part.strip().split("=") for part in cache_duration_header_value.split(",")])

            if "public" in cache_duration_parts:
                result["cache_timeout"] = int(cache_duration_parts["max-age"])

        if req.status_code == 200:
            if response_content_type == "application/json":
                result.update(json.loads(req.text))
            elif response_content_type == "application/jwt":
                jws = jwkest.jws.factory(req.text)

                if jws is not None and len(jws.jwt.part) >= 2:
                    result["active"] = True
                    result.update(json.loads(jws.jwt.part[1]))
            else:
                 # Text or HTML presumably
                warnings.warn("Response type from introspection endpoint was unsupported, response_type = " +
                              response_content_type)

                raise Exception("Response type is from introspect endpoint is " + response_content_type, req.text)
        elif req.status_code == 204:
            result.update(dict(active=False))
        else:
            raise Exception("HTTP POST error from introspection: %s" % req.status_code)

        return result

    def validate(self, token):

        now = calendar.timegm(datetime.utcnow().utctimetuple())

        # Lookup in cache:
        cached_response = self._token_cache.get(token)
        if cached_response is not None:
            if cached_response['active']:
                if cached_response['exp'] >= now:
                    return {"subject": cached_response['sub'],
                            "scope": cached_response['scope'],
                            "active": True}
            else:
                return dict(active=False)

        introspect_response = self.introspect_token(token)
        cache_timeout = 0

        if "cache_timeout" in introspect_response:
            cache_timeout = introspect_response["cache_timeout"]
        elif "exp" in introspect_response:
            cache_timeout = introspect_response["exp"] - now

        if "active" not in introspect_response:
            # The token isn't know to be active, so we'll never introspect it again
            introspect_response["active"] = False

            self._token_cache.set(token, introspect_response, timeout=cache_timeout)

            raise OpaqueValidatorException("No active field in introspection response")

        self._token_cache.set(token, introspect_response, timeout=cache_timeout)

        if not introspect_response['active']:
            return {"active": False}

        if 'sub' not in introspect_response:
            raise OpaqueValidatorException("Missing sub field in introspection response")

        if 'exp' not in introspect_response:
            raise OpaqueValidatorException("Missing exp field in introspection response")

        if 'scope' not in introspect_response:
            raise OpaqueValidatorException("Missing scope field in introspection response")

        return {"subject": introspect_response['sub'],
                "scope": introspect_response['scope'],
                "active": True}
