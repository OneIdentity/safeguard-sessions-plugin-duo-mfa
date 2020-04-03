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
import base64
import logging
from ssl import SSLError
from socket import error as SocketError
from http.client import HTTPException
from duo_client.auth import Auth
from safeguard.sessions.plugin.mfa_client import (
    MFAClient,
    MFAAuthenticationFailure,
    MFACommunicationError,
    MFAServiceUnreachable,
)
from safeguard.sessions.plugin import AAResponse

logger = logging.getLogger(__name__)


class Client(MFAClient):
    def __init__(
        self,
        ikey,
        skey,
        host,
        timeout=30,
        ignore_connection_error=False,
        second_try=None,
        disable_echo=False,
        http_proxy_settings=None,
    ):
        self._duo = Auth(ikey=ikey, skey=skey, host=host, timeout=timeout)
        self._second_try = second_try
        self._disable_echo = disable_echo
        self._set_http_proxy_settings(http_proxy_settings)
        super().__init__("SPS Duo Plugin", ignore_connection_error)
        logger.info("Client initialized.")

    def _set_http_proxy_settings(self, http_proxy_settings):
        if not http_proxy_settings or not http_proxy_settings.get("server") or not http_proxy_settings.get("port"):
            return
        if http_proxy_settings.get("username") and http_proxy_settings.get("password"):
            # rfc7617 The 'Basic' HTTP Authentication Scheme
            encoded_user_pwd = base64.b64encode(
                "{}:{}".format(http_proxy_settings.get("username"), http_proxy_settings.get("password")).encode("utf-8")
            )
            headers = {"Proxy-Authorization": "Basic " + encoded_user_pwd.decode("ascii")}
        else:
            headers = None
        logger.info(
            "Setting proxy in Duo client to server={} port={} {}".format(
                http_proxy_settings.get("server"),
                http_proxy_settings.get("port"),
                "with basic authentication" if headers else "without authentication",
            )
        )
        self._duo.set_proxy(
            host=http_proxy_settings.get("server"), port=int(http_proxy_settings.get("port")), headers=headers
        )

    @classmethod
    def from_config(cls, plugin_configuration, section="duo", second_try=None, http_proxy_settings=None):
        ikey = plugin_configuration.get(section, "ikey", required=True)
        skey = plugin_configuration.get(section, "skey", required=True)
        host = plugin_configuration.get(section, "host", required=True)
        timeout = plugin_configuration.getint(section, "timeout", 60)
        ignore_connection_error = plugin_configuration.getboolean(section, "ignore_connection_error")
        disable_echo = plugin_configuration.getboolean("auth", "disable_echo", default=False)
        return cls(
            ikey,
            skey,
            host,
            timeout=timeout,
            ignore_connection_error=ignore_connection_error,
            second_try=second_try,
            disable_echo=disable_echo,
            http_proxy_settings=http_proxy_settings,
        )

    def otp_authenticate(self, username, otp):
        result = False
        try:
            preauth = self._check_preauth(username)
            if self._is_bypass_user(preauth):
                return self._log_bypass_and_create_aa_response()

            logger.info("Account found, running passcode authentication.")
            auth = self._duo.auth(factor="passcode", username=username, passcode=str(otp))
            result = self._check_auth_result(auth)
        except (RuntimeError, KeyError) as e:
            raise MFACommunicationError(self._construct_exception_message(e))
        except (SSLError, SocketError, HTTPException) as e:
            raise MFAServiceUnreachable(self._construct_exception_message(e))
        return result

    def push_authenticate(self, username):
        try:
            preauth = self._check_preauth(username)
            if self._is_bypass_user(preauth):
                return self._log_bypass_and_create_aa_response()

            devices = preauth["devices"]
            if not [dev for dev in devices if "push" in dev.get("capabilities", [])]:
                raise MFAAuthenticationFailure("No push capable device enrolled.")
            logger.info("Account and device found, running push authentication.")
            auth = self._duo.auth(factor="push", username=username, device="auto")  # First push device is used.
            self._check_auth_result(auth)
        except (RuntimeError, KeyError) as e:
            raise MFACommunicationError(self._construct_exception_message(e))
        except (SSLError, SocketError, HTTPException) as e:
            if isinstance(e, SSLError) and any([True for arg in e.args if "timed out" in arg]):
                raise MFAAuthenticationFailure("Push request timed out.")
            raise MFAServiceUnreachable(self._construct_exception_message(e))
        return True

    def _log_bypass_and_create_aa_response(self):
        msg = "User configured as bypass user on Duo."
        logger.info(msg)
        return AAResponse.accept(reason=msg)

    def _is_bypass_user(self, preauth):
        result = preauth["result"]
        return result == "allow"

    def _check_preauth(self, username):
        logger.debug("Looking up user.")
        preauth = self._duo.preauth(username=username)
        if preauth["result"] not in ("auth", "allow"):
            raise MFAAuthenticationFailure(preauth["status_msg"])
        return preauth

    def _check_auth_result(self, auth_result):
        msg = "This passcode has already been used. Please generate a new passcode and try again."
        if auth_result["status_msg"] == msg and not self._second_try:
            return AAResponse.need_info(**{"key": "otp", "question": msg + " ", "disable_echo": self._disable_echo})
        if auth_result["result"] != "allow":
            raise MFAAuthenticationFailure(auth_result["status_msg"])
        return True

    @staticmethod
    def _construct_exception_message(exception):
        if hasattr(exception, "data"):
            message = exception.data.get("message", "")
        elif hasattr(exception, "message"):
            message = exception.message
        elif hasattr(exception, "args"):
            message = exception.args
        else:
            message = ""
        return "Exception: {}, message: {}".format(type(exception).__name__, message)
