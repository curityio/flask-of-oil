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

import base64
import random
import string


def base64_urldecode(string):
    string.replace('-', '+')
    string.replace('_', '/')
    string += '=' * (4 - (len(string) % 4))
    return base64.b64decode(string)


def decode_payload(token):
    if token and len(token.split('.')) == 3:
        token_part = token.split('.')[1]
        token_part += '=' * (4 - len(token_part) % 4)
        return base64.b64decode(token_part)
    return token


def generate_random_string():
    """
    :return: a random string to be used as key in the session store
    """
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(20))
