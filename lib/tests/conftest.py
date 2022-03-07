#
#   Copyright 2022 One Identity LLC.
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
import pytest
import duo_client.client
from duo_client.client import CertValidatingHTTPSConnection
from vcr.stubs import VCRHTTPSConnection
from ..client import Client


class DuoVCRHTTPSConnection(VCRHTTPSConnection, CertValidatingHTTPSConnection):
    _baseclass = CertValidatingHTTPSConnection


@pytest.fixture(scope='module')
def vcr_config():
    return {'filter_headers': ['authorization'],
            'filter_post_data_parameters': ['passcode'],
            'custom_patches': ((duo_client.client, 'CertValidatingHTTPSConnection', DuoVCRHTTPSConnection),)}


@pytest.fixture
def duo_user(site_parameters):
    return site_parameters['username']


@pytest.fixture
def duo_bypass_user(site_parameters):
    return site_parameters["bypass_username"]


@pytest.fixture
def duo_wrong_user(site_parameters):
    return site_parameters['wrong_username']


@pytest.fixture
def duo_user_without_device(site_parameters):
    return site_parameters['username_without_device']


@pytest.fixture
def duo_passcode(site_parameters):
    return site_parameters['passcode']


@pytest.fixture
def duo_wrong_passcode(site_parameters):
    return site_parameters['wrong_passcode']


@pytest.fixture
def client(site_parameters):
    return Client(
        site_parameters['ikey'],
        site_parameters['skey'],
        site_parameters['host']
    )
