# #########################################################################
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

import re

from flask import request, abort, g, make_response
from jwt_validator import JwtValidator
from opaque_validator import OpaqueValidator
from functools import wraps


class OAuthFilter:
    def __init__(self, verify_ssl=True):
        self.protected_endpoints = {}
        self.configured = False
        self.verify_ssl = verify_ssl

    def configure_with_jwt(self, jwks_url, issuer, audience, scopes=[]):
        """

        :param jwks_url:
        :param issuer:
        :param audience:
        :param scopes:
        :return:
        """
        self.validator = JwtValidator(jwks_url, issuer, audience, self.verify_ssl)
        self.scopes = scopes

    def configure_with_opaque(self, introspection_url, client_id, client_secret, scopes=[]):
        """

        :param introspection_url:
        :param client_id:
        :param client_secret:
        :param scopes:
        :return:
        """
        self.validator = OpaqueValidator(introspection_url, client_id, client_secret, self.verify_ssl)
        self.scopes = scopes

    def _add_protected_endpoint(self, func, scopes):
        self.protected_endpoints[func] = scopes

    def _extract_access_token(self, request):
        """
        Extract the token from the Authorization header
        OAuth Access Tokens are placed in the header in the form "Bearer XYZ", so Bearer
        needs to be removed and the whitespaces trimmed.

        The method will abort if no token is present, and return a 401
        :param request: The incoming flask request
        :return: the stripped token
        """
        authorization_header = request.headers.get("authorization")

        if authorization_header is None:
            abort(401)

        authorization_header_parts = re.split("\s+", authorization_header)
        authorization_type = authorization_header_parts[0].lower()

        # Extract the token from the Bearer string
        if authorization_type != "bearer":
            abort(401)

        return authorization_header_parts[1] if len(authorization_header_parts) >= 2 else None

    def _authorize(self, scope, endpoint_scopes=None):
        if isinstance(scope, (list, tuple)):
            incoming_scopes = scope
        else:
            incoming_scopes = re.split("\s+", scope)

        if endpoint_scopes is None:
            required_scopes = self.scopes
        else:
            required_scopes = endpoint_scopes

        return all(s in incoming_scopes for s in required_scopes)

    def protect(self, scopes=[]):
        """
        This is a decorator function that can be used on a flask route:
        @_oauth.protect(["read","write]) or @_oauth.protect()
        :param scopes: The scopes that are required for the endpoint protected
        """
        def decorator(f):
            @wraps(f)
            def inner_decorator(*args, **kwargs):
                if self.filter(scopes=scopes) is None:
                    return f(*args, **kwargs)
                else:
                    abort(500)

            return inner_decorator

        return decorator

    def filter(self, scopes=None):
        print "Request method = " + str(request.method)
        print "Authorization Header " + str(request.headers.get("authorization"))
        token = self._extract_access_token(request)

        try:
            validated_token = self.validator.validate(token)
        except Exception:
            abort(make_response("Server Error", 500))

        if not validated_token['active']:
            abort(make_response("Access Denied", 401))

        # Authorize scope
        authorized = self._authorize(validated_token['scope'], endpoint_scopes=scopes)
        if not authorized:
            abort(make_response("Forbidden", 403))

        # Set the user info in a context global variable
        g.user = validated_token['subject']

        return None

