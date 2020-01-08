# Flask OAuth Filter - an OAuth Interceptor Logic

This library provides an extension for protecting APIs with OAuth when using Flask.

## Installation

You can either install this module with pip:
```pip install -U flask-of-oil```

Or copy the flask_of_oil folder in your project and install the requirements in ```requirements.txt``` using pip or pipenv

## Usage

This filter can be used in two ways with Flask, either to run before all routes with the same authorization requirement,
which protects all endpoints. Many times however it's desirable to only protect certain endpoints, which then can be done
using the `decorator` pattern described below.

### Using filter as a before_request filter that runs before ALL routes

When running the filter [before_request](http://flask.pocoo.org/docs/0.11/api/#flask.Flask.before_request)  *all* routes, the same configuration will apply to all routes. So if the filter is
 configured to require a scope of "read" then all routes will require that scope. If routes have different needs then
 the decorator pattern should be used (see next section).

**Example using before_request**

```python
import json
from flask import g, Flask
from flask_of_oil.oauth_filter import OAuthFilter

_app = Flask(__name__)
_oauth = OAuthFilter(verify_ssl=True)
_app.before_request(_oauth.filter)

@_app.route('/hello_world')
def hello_world():
    """
    :return: Returns a very useful JSON message when accessed.
    """
    print("OAuth Access token used for access")
    return json.dumps({"hello": g.user})
```


### Using filter as a decorator that runs before specific routes

Instead of setting the `before_request` a decorator can be added to the route that should be protected. This also enables the routes to have
 different scope requirements which could be handy.

*Important: The oauth decorator needs to be CLOSEST to the function*

```python
import json
from flask import g, Flask
from flask_of_oil.oauth_filter import OAuthFilter

_app = Flask(__name__)
_oauth = OAuthFilter(verify_ssl=True)

@_app.route('/hello_world')
@_oauth.protect(["read"])
def hello_world():
    """
    :return: Returns a very useful JSON message when accessed.
    """
    print("OAuth Access token used for access")
    return json.dumps({"hello": g.user})
```

### Authorizing the request based on scopes

The scope parameter of the protect decorator must either be a list or a space separated string:
``` 
["scope1", "scope2]
or 
"scope1 scope2"
```

### Authorizing the request based on claims

The incoming request can also be authorized based on claims, or a combination of claims and scopes.
The claims parameter of the protect decorator method has to be a `dict`, with keys the claims that are required 
for the request to be allowed. The value `None` instructs the filter to not check the value for the specific claim. 

```python
# Only allow requests where the incoming access token has the scope read and it contains a claim named MyGoodClaim
@_oauth.protect(scope=["read"], claims={"MyGoodClaim": None})
```
```python
# Only allow requests where the incoming access token has the scope write and it contains a claim named MyGoodClaim with value MyGoodValue
@_oauth.protect(scope=["write"], claims={"MyGoodClaim": "MyGoodValue"})
```


## Initializing the filter

**Filter global variable**

The OAuth filter should be setup the same way as Flask, a global reference and then initialized in main (or with the application)
The initialization depends on the type of tokens received. See the following examples.

```python
from flask import g, Flask
from flask_of_oil.oauth_filter import OAuthFilter

_app = Flask(__name__)
_oauth = OAuthFilter(verify_ssl=True)
```

**Using Opaque tokens**

When using Opaque tokens, the filter needs to resolve the reference by calling the introspection endpoint of the
OAuth server, this endpoint requires client credentials so the API needs to be a client of the OAuth server with the
permission to introspect tokens.

```python
if __name__ == '__main__':
    # configure the oauth filter
    _oauth.configure_with_opaque("https://oauth-server-host/oauth/v2/introspection", "api-client-id", "api-client-secret")

    # initiate the Flask app
    _app.run("localhost", debug=True, port=8000,
             ssl_context="adhoc")
```

**Using JWT tokens**

When using JWT (JWS) tokens, the filter will validate the signature of the token with the key that is provided on the
JWKS (Json Web Key Service) endpoint. The JWT contains a key id (kid) that is matched against the available public keys
on the OAuth server and then validated with that key.

```python
if __name__ == '__main__':
    # configure the oauth filter
    _oauth.configure_with_jwt("https://oauth-server-host/oauth/v2/metadata/jwks", "configured-issuer", "audience-of-token")

    # initiate the Flask app
    _app.run("localhost", debug=True, port=8000,
             ssl_context="adhoc")
```


## Access token claims in Request object

When the filter accepts the request, it sets the `request.claims` context local variable for that request with all
the token claims. For JWT tokens, this is the JWT payload and for opaque tokens the introspection response. 

For example, in the subject of the Authorization can be accessed like so `request.claims.sub` 

## Handling errors

The filter may abort the request if the Access token is invalid or if the scopes in the access token doesn't match the
required scopes for the route.

**401 Unauthorized**

When an invalid token is presented the filter will give a 401 unauthorized.
To customize the response, use Flasks [errorhandler](http://flask.pocoo.org/docs/0.11/api/#flask.Flask.errorhandler) to add a response.

```python
@_app.errorhandler(401)
def unauthorized(error):
    return json.dumps({'error': "unauthorized",
                       "error_description": "No valid access token found"}), \
           401, {'Content-Type': 'application/json; charset=utf-8'}
```

**403 Forbidden**

When a valid token is presented the filter but it's missing the appropriate scopes then the request is aborted
with a 403 Forbidden.

```python
@_app.errorhandler(403)
def forbidden(error):
    return json.dumps({'error': "forbidden",
                       "error_description": "Access token is missing appropriate scopes"}), \
           403, {'Content-Type': 'application/json; charset=utf-8'}
```


## Questions and Support

For questions and support, contact Curity AB:

> Curity AB
>
> info@curity.io
> https://curity.io


Copyright (C) 2016 Curity AB.