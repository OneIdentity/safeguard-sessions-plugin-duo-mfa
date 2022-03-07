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
from ssl import SSLError
from unittest.mock import patch
from safeguard.sessions.plugin.mfa_client import MFAAuthenticationFailure, MFACommunicationError, MFAServiceUnreachable
from safeguard.sessions.plugin import AAResponse
from ..client import Client
from six.moves.http_client import NotConnected


@pytest.fixture
def inject_connection_error(mocker):
    request_mock = mocker.patch("duo_client.client.Client._make_request")
    request_mock.side_effect = NotConnected


@pytest.mark.interactive
def test_otp_auth_ok(client, duo_user, interactive):
    otp = interactive.askforinput("Please enter OTP generated with DUO device, e.g. DUO mobile")
    assert client.otp_authenticate(duo_user, otp)


@pytest.mark.interactive
def test_otp_ask_for_new_otp_if_already_used(client, duo_user, interactive):
    otp = interactive.askforinput("Please enter the previous OTP")
    result = client.otp_authenticate(duo_user, otp)
    assert result == AAResponse.need_info(**{
        'key': 'otp',
        'question': 'This passcode has already been used. Please generate a new passcode and try again. ',
        'disable_echo': False})


@pytest.mark.interactive
def test_push_auth_ok(client, duo_user, interactive):
    interactive.message("Please ACCEPT the push notification in DUO application")
    assert client.push_authenticate(duo_user)


@pytest.mark.interactive
def test_push_auth_user_decline(client, duo_user, interactive):
    interactive.message("Please REJECT the push notification in DUO application")
    with pytest.raises(MFAAuthenticationFailure) as e:
        client.push_authenticate(duo_user)

    assert e.match('Login request denied')


@pytest.mark.interactive
def test_bypass_auth_without_bypass_code_push(client, duo_bypass_user, interactive):
    result = client.push_authenticate(duo_bypass_user)
    assert result == AAResponse.accept(reason="User configured as bypass user on Duo.")


@pytest.mark.interactive
def test_bypass_auth_without_bypass_code_otp(client, duo_bypass_user, interactive):
    otp = interactive.askforinput("Please enter OTP whatever you like")
    result = client.otp_authenticate(duo_bypass_user, otp)
    assert result == AAResponse.accept(reason="User configured as bypass user on Duo.")


@patch('lib.client.Auth')
def test_push_auth_timeout(patcher, duo_user, interactive):
    with pytest.raises(MFAAuthenticationFailure) as e:
        instance = patcher.return_value
        instance.preauth.return_value = {'result': 'auth', 'devices': [{'capabilities': ['push']}]}
        instance.auth.side_effect = SSLError('The read operation timed out.')

        client = Client('ikey', 'skey', 'host')
        client.push_authenticate(duo_user)

    assert e.match('timed out')


def test_bypass_auth_ok(client, duo_user, duo_passcode):
    assert client.otp_authenticate(duo_user, duo_passcode)


def test_otp_auth_wrong_passcode(client, duo_user, duo_wrong_passcode):
    with pytest.raises(MFAAuthenticationFailure) as e:
        client.otp_authenticate(duo_user, duo_wrong_passcode)

    assert e.match('Incorrect passcode')


def test_otp_auth_unknown_host(client, duo_user, duo_passcode, inject_connection_error):
    with pytest.raises(MFAServiceUnreachable):
        client.otp_authenticate(duo_user, duo_passcode)


def test_otp_auth_unknown_user(client, duo_wrong_user, duo_passcode):
    with pytest.raises(MFAAuthenticationFailure) as e:
        client.otp_authenticate(duo_wrong_user, duo_passcode)

    assert e.match('Enroll an authentication')


def test_otp_auth_invalid_apikey(client, duo_user, duo_passcode):
    with pytest.raises(MFACommunicationError) as e:
        client._duo.skey = ''
        client.otp_authenticate(duo_user, duo_passcode)

    assert e.match('Invalid signature')


def test_push_auth_no_push_device(client, duo_user_without_device):
    with pytest.raises(MFAAuthenticationFailure) as e:
        client.push_authenticate(duo_user_without_device)

    assert e.match('No push capable')


def test_push_auth_unkown_user(client, duo_wrong_user):
    with pytest.raises(MFAAuthenticationFailure) as e:
        client.push_authenticate(duo_wrong_user)

    assert e.match('Enroll an authentication')


def test_push_auth_unknown_host(client, duo_user, inject_connection_error):
    with pytest.raises(MFAServiceUnreachable):
        client.push_authenticate(duo_user)


def test_push_auth_invalid_apikey(client, duo_user):
    with pytest.raises(MFACommunicationError) as e:
        client._duo.skey = ''
        client.push_authenticate(duo_user)

    assert e.match('Invalid signature')


def test_duo_set_proxy():
    client = Client('ikey', 'skey', 'host', proxy='proxy')
    assert (client._duo.proxy_host == 'proxy' and client._duo.proxy_port == 3128)
