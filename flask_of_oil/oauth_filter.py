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
import json

from flask import request, abort
from flask_of_oil.jwt_validator import JwtValidator
from flask_of_oil.opaque_validator import OpaqueValidator
from functools import wraps

from flask_of_oil.tools import base64_urldecode


class OAuthFilter:
    def __init__(self, verify_ssl=True):
        self.protected_endpoints = {}
        self.configured = False
        self.verify_ssl = verify_ssl
        self.logger = logging.getLogger(__name__)
        self.validators = dict()
        self.scopes = list()

    def configure_with_jwt(self, jwks_url, issuer, audience, scopes=None):
        """

        :param jwks_url:
        :param issuer:
        :param audience:
        :param scopes:
        :return:
        """
        self.validators["*"] = JwtValidator(jwks_url, issuer, audience, self.verify_ssl)

        if scopes is not None:
            self.scopes = scopes

    def configure_with_multiple_jwt_issuers(self, issuers, audience=None, scopes=None):
        """

        :param issuers: List of issuer values.
        :param audience: The expected value of the aud claim.
        :param scopes: List of required scopes.
        :return:
        """

        if scopes is not None:
            self.scopes = scopes

        for issuer in issuers:
            if isinstance(issuer, str):
                jwks_url = issuer + "/jwks"
                self.validators[issuer] = JwtValidator(jwks_url, issuer, audience, self.verify_ssl)
            elif isinstance(issuer, dict):
                self.validators[issuer['name']] = JwtValidator(issuer['url'], issuer['name'], issuer['audience'],
                                                               self.verify_ssl)

    def configure_with_opaque(self, introspection_url, client_id, client_secret, scopes=None):
        """

        :param introspection_url:
        :param client_id:
        :param client_secret:
        :param scopes:
        :return:
        """
        self.validators["*"] = OpaqueValidator(introspection_url, client_id, client_secret, self.verify_ssl)

        if scopes is not None:
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

    def _authorize(self, token_claims, endpoint_scopes, endpoint_claims, endpoint_audience):

        if endpoint_audience is not None:
            if not isinstance(endpoint_audience, list):
                endpoint_audience = [endpoint_audience]

            if not isinstance(token_claims['aud'], list):
                token_claims['aud'] = [token_claims['aud']]

            if len(set(endpoint_audience)&set(token_claims['aud'])) == 0:
                return False

        if endpoint_claims is None:
            endpoint_claims = {}

        for claim in endpoint_claims:
            if claim not in token_claims:
                return False

            if endpoint_claims[claim] is not None:
                if isinstance(token_claims[claim], list):
                    if isinstance(endpoint_claims[claim], list):
                        if len(set(token_claims[claim])&set(endpoint_claims[claim])) == 0:
                            return False
                    else:
                        if endpoint_claims[claim] not in token_claims[claim]:
                            return False
                else:
                    if token_claims[claim] != endpoint_claims[claim]:
                        return False

        if 'scope' not in token_claims:
            token_claims['scope'] = []
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

    def protect(self, scopes=None, claims=None, audience=None):
        """
        This is a decorator function that can be used on a flask route:
        @_oauth.protect(["read","write]) or @_oauth.protect()
        :param claims: The claims that are required for the protected endpoint (dict)
        :param scopes: The scopes that are required for the protected endpoint (list or space separated string)
        :param audience: The audience that is required for the protected endpoint (string)
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
                if self.filter(scopes=scopes, claims=claims, audience=audience) is None:
                    return f(*args, **kwargs)
                else:
                    abort(500)

            return inner_decorator

        return decorator


    def filter(self, scopes=None, claims=None, audience=None):
        self.logger.debug("Request method = " + str(request.method))
        token = self._extract_access_token(request)
        validated_token = dict(active=False)
        self.logger.debug("Access token " + token)

        # noinspection PyBroadException
        try:
            if "*" in self.validators:
                validated_token = self.validators["*"].validate(token)
            else:
                # See if we can determine the issuer; we'll use that as the key to find
                # the validator.
                parts = token.split(".")

                if len(parts) == 3:
                    payload = json.loads(base64_urldecode(parts[1]))
                    issuer = payload["iss"]

                    if issuer in self.validators:
                        validated_token = self.validators[issuer].validate(token)
        except Exception:
            abort(500)
            return

        if not validated_token['active']:
            abort(401)

        # Authorize scope
        authorized = self._authorize(validated_token, endpoint_scopes=scopes, endpoint_claims=claims,
                                     endpoint_audience=audience)
        if not authorized:
            abort(403)

        # Set the user info in a context global variable
        request.claims = validated_token

        return None
