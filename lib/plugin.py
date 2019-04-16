#
#   Copyright (c) 2019 One Identity
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#
from safeguard.sessions.plugin import AAPlugin
from safeguard.sessions.plugin.plugin_base import cookie_property
from .client import Client


class Plugin(AAPlugin):
    def __init__(self, configuration):
        super().__init__(configuration)

    @cookie_property
    def second_try(self):
        return False

    def do_authenticate(self):
        client = self._construct_mfa_client()
        auth_result = client.execute_authenticate(self.username, self.mfa_identity, self.mfa_password)
        if auth_result['verdict'] == 'NEEDINFO':
            self.second_try = True
        return auth_result

    def _construct_mfa_client(self):
        return Client.from_config(self.plugin_configuration, second_try=self.second_try)
