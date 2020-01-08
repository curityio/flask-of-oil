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

import logging
from functools import wraps

from flask import request, abort, make_response

from flask_of_oil.jwt_validator import JwtValidator
from flask_of_oil.opaque_validator import OpaqueValidator


class OAuthFilter:
    def __init__(self, verify_ssl=True):
        self.protected_endpoints = {}
        self.configured = False
        self.verify_ssl = verify_ssl
        self.logger = logging.getLogger(__name__)
        self.validator = None
        self.scopes = None

    def configure_with_jwt(self, jwks_url, issuer, audience, scopes=None):
        """

        :param jwks_url:
        :param issuer:
        :param audience:
        :param scopes:
        :return:
        """
        if scopes is None:
            scopes = []
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

    @staticmethod
    def _extract_access_token(incoming_request=None):
        """
        Extract the token from the Authorization header
        OAuth Access Tokens are placed in the header in the form "Bearer XYZ", so Bearer
        needs to be removed and the whitespaces trimmed.

        The method will abort if no token is present, and return a 401
        :param incoming_request: The incoming flask request
        :return: the stripped token
        """

        authorization_header = incoming_request.headers.get("authorization", type=str)
        query_param_access_token = incoming_request.args.get("access_token", type=str)

        if authorization_header is None and query_param_access_token is None:
            abort(401)

        if authorization_header is not None:
            authorization_header_parts = authorization_header.split()
            authorization_type = authorization_header_parts[0].lower()

            # Extract the token from the Bearer string
            if authorization_type != "bearer":
                abort(401)

            return authorization_header_parts[1] if len(authorization_header_parts) >= 2 else None

        return query_param_access_token

    def _authorize(self, token_claims, endpoint_scopes, endpoint_claims):

        for claim in endpoint_claims:
            if claim not in token_claims or \
                    (endpoint_claims[claim] is not None and token_claims[claim] != endpoint_claims[claim]):
                return False

        scope = token_claims['scope']
        if isinstance(token_claims['scope'], (list, tuple)):
            incoming_scopes = scope
        else:
            incoming_scopes = scope.split()

        if endpoint_scopes is None:
            required_scopes = self.scopes
        else:
            required_scopes = endpoint_scopes

        return all(s in incoming_scopes for s in required_scopes)

    def protect(self, scopes=None, claims=None):
        """
        This is a decorator function that can be used on a flask route:
        @_oauth.protect(["read","write]) or @_oauth.protect()
        :param claims: The claims that are required for the protected endpoint (dict)
        :param scopes: The scopes that are required for the protected endpoint (list or space separated string)
        """

        if scopes is None:
            scopes = []

        if not isinstance(scopes, list):
            scopes = scopes.split()

        if claims is None:
            claims = {}

        if not isinstance(claims, dict):
            claims = {}
            self.logger.warning("claims is not a dict and will be ignored")

        def decorator(f):
            @wraps(f)
            def inner_decorator(*args, **kwargs):
                if self.filter(scopes=scopes, claims=claims) is None:
                    return f(*args, **kwargs)
                else:
                    abort(500)

            return inner_decorator

        return decorator

    def filter(self, scopes=None, claims=None):
        self.logger.debug("Request method = " + str(request.method))
        token = self._extract_access_token(request)
        self.logger.debug("Access token " + token)

        # noinspection PyBroadException
        try:
            validated_token = self.validator.validate(token)
        except Exception:
            abort(make_response("Server Error", 500))
            return

        if not validated_token['active']:
            abort(make_response("Access Denied", 401))

        # Authorize scope
        authorized = self._authorize(validated_token, endpoint_scopes=scopes, endpoint_claims=claims)
        if not authorized:
            abort(make_response("Forbidden", 403))

        # Set the user info in a context global variable
        request.claims = validated_token

        return None
