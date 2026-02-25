"""Library tests."""
import base64
import hashlib
import json
from requests import Response

import srp
import srp._pysrp as _pysrp

from pyicloud import base

from .const import (
    AUTHENTICATED_USER,
    REQUIRES_2FA_USER,
    REQUIRES_2FA_TOKEN,
    VALID_TOKEN,
    VALID_USERS,
    VALID_PASSWORD,
    VALID_COOKIE,
    VALID_2FA_CODE,
    VALID_TOKENS,
)
from .const_login import (
    AUTH_OK,
    LOGIN_WORKING,
    LOGIN_2FA,
    TRUSTED_DEVICES,
    TRUSTED_DEVICE_1,
    VERIFICATION_CODE_OK,
    VERIFICATION_CODE_KO,
)
from .const_account import ACCOUNT_DEVICES_WORKING, ACCOUNT_STORAGE_WORKING
from .const_account_family import ACCOUNT_FAMILY_WORKING
from .const_drive import (
    DRIVE_FOLDER_WORKING,
    DRIVE_ROOT_INVALID,
    DRIVE_SUBFOLDER_WORKING,
    DRIVE_ROOT_WORKING,
    DRIVE_FILE_DOWNLOAD_WORKING,
)
from .const_findmyiphone import FMI_FAMILY_WORKING

# SRP mock constants
SRP_SALT = b"\x01" * 16
SRP_ITERATIONS = 20
SRP_KEY_LENGTH = 32
SRP_C = "srp_session_token"


def _compute_srp_vkey(username, password, salt, iterations, key_length):
    """Compute SRP verification key for the mock."""
    srp.rfc5054_enable()
    srp.no_username_in_x()
    _pysrp.rfc5054_enable()
    _pysrp.no_username_in_x()

    # Derive password the same way the client does
    password_hash = hashlib.sha256(password.encode("utf-8")).digest()
    derived = hashlib.pbkdf2_hmac("sha256", password_hash, salt, iterations, key_length)

    # Compute verification key using pure Python SRP internals
    N, g = _pysrp.get_ng(srp.NG_2048, None, None)
    hash_class = _pysrp._hash_map[srp.SHA256]
    x = _pysrp.gen_x(hash_class, salt, username, derived)
    v = pow(g, x, N)
    return _pysrp.long_to_bytes(v)


class ResponseMock(Response):
    """Mocked Response."""

    def __init__(self, result, status_code=200, **kwargs):
        """Set up response mock."""
        Response.__init__(self)
        self.result = result
        self.status_code = status_code
        self.raw = kwargs.get("raw")
        self.headers = kwargs.get("headers", {})

    @property
    def text(self):
        """Return text."""
        return json.dumps(self.result)


class PyiCloudSessionMock(base.PyiCloudSession):
    """Mocked PyiCloudSession."""

    def request(self, method, url, **kwargs):
        """Make the request."""
        params = kwargs.get("params")
        headers = kwargs.get("headers")
        data = json.loads(kwargs.get("data", "{}"))

        # Login
        if self.service.SETUP_ENDPOINT in url:
            if "accountLogin" in url and method == "POST":
                if data.get("dsWebAuthToken") not in VALID_TOKENS:
                    self._raise_error(None, "Unknown reason")
                if data.get("dsWebAuthToken") == REQUIRES_2FA_TOKEN:
                    return ResponseMock(LOGIN_2FA)
                return ResponseMock(LOGIN_WORKING)

            if "listDevices" in url and method == "GET":
                return ResponseMock(TRUSTED_DEVICES)

            if "sendVerificationCode" in url and method == "POST":
                if data == TRUSTED_DEVICE_1:
                    return ResponseMock(VERIFICATION_CODE_OK)
                return ResponseMock(VERIFICATION_CODE_KO)

            if "validateVerificationCode" in url and method == "POST":
                TRUSTED_DEVICE_1.update({"verificationCode": "0", "trustBrowser": True})
                if data == TRUSTED_DEVICE_1:
                    self.service.user["apple_id"] = AUTHENTICATED_USER
                    return ResponseMock(VERIFICATION_CODE_OK)
                self._raise_error(None, "FOUND_CODE")

            if "validate" in url and method == "POST":
                if headers.get("X-APPLE-WEBAUTH-TOKEN") == VALID_COOKIE:
                    return ResponseMock(LOGIN_WORKING)
                self._raise_error(None, "Session expired")

        if self.service.AUTH_ENDPOINT in url:
            if "signin/init" in url and method == "POST":
                if data.get("accountName") not in VALID_USERS:
                    self._raise_error(None, "Unknown reason")

                A = base64.b64decode(data.get("a"))
                vkey = _compute_srp_vkey(
                    data.get("accountName"),
                    VALID_PASSWORD,
                    SRP_SALT,
                    SRP_ITERATIONS,
                    SRP_KEY_LENGTH,
                )
                self._srp_verifier = srp.Verifier(
                    data.get("accountName"),
                    SRP_SALT,
                    vkey,
                    A,
                    hash_alg=srp.SHA256,
                    ng_type=srp.NG_2048,
                )
                s, B = self._srp_verifier.get_challenge()
                return ResponseMock(
                    {
                        "salt": base64.b64encode(SRP_SALT).decode(),
                        "b": base64.b64encode(B).decode(),
                        "c": SRP_C,
                        "iteration": SRP_ITERATIONS,
                    }
                )

            if "signin/complete" in url and method == "POST":
                M = base64.b64decode(data.get("m1"))
                self._srp_verifier.verify_session(M)

                if not self._srp_verifier.authenticated():
                    self._raise_error(None, "Unknown reason")

                account_name = data.get("accountName")
                if account_name == REQUIRES_2FA_USER:
                    self.service.session_data["session_token"] = REQUIRES_2FA_TOKEN
                else:
                    self.service.session_data["session_token"] = VALID_TOKEN
                return ResponseMock(AUTH_OK)

            if "securitycode" in url and method == "POST":
                if data.get("securityCode", {}).get("code") != VALID_2FA_CODE:
                    self._raise_error(None, "Incorrect code")

                self.service.session_data["session_token"] = VALID_TOKEN
                return ResponseMock("", status_code=204)

            if "trust" in url and method == "GET":
                return ResponseMock("", status_code=204)

        # Account
        if "device/getDevices" in url and method == "GET":
            return ResponseMock(ACCOUNT_DEVICES_WORKING)
        if "family/getFamilyDetails" in url and method == "GET":
            return ResponseMock(ACCOUNT_FAMILY_WORKING)
        if "setup/ws/1/storageUsageInfo" in url and method == "GET":
            return ResponseMock(ACCOUNT_STORAGE_WORKING)

        # Drive
        if (
            "retrieveItemDetailsInFolders" in url
            and method == "POST"
            and data[0].get("drivewsid")
        ):
            if data[0].get("drivewsid") == "FOLDER::com.apple.CloudDocs::root":
                return ResponseMock(DRIVE_ROOT_WORKING)
            if data[0].get("drivewsid") == "FOLDER::com.apple.CloudDocs::documents":
                return ResponseMock(DRIVE_ROOT_INVALID)
            if (
                data[0].get("drivewsid")
                == "FOLDER::com.apple.CloudDocs::1C7F1760-D940-480F-8C4F-005824A4E05B"
            ):
                return ResponseMock(DRIVE_FOLDER_WORKING)
            if (
                data[0].get("drivewsid")
                == "FOLDER::com.apple.CloudDocs::D5AA0425-E84F-4501-AF5D-60F1D92648CF"
            ):
                return ResponseMock(DRIVE_SUBFOLDER_WORKING)
        # Drive download
        if "com.apple.CloudDocs/download/by_id" in url and method == "GET":
            if params.get("document_id") == "516C896C-6AA5-4A30-B30E-5502C2333DAE":
                return ResponseMock(DRIVE_FILE_DOWNLOAD_WORKING)
        if "icloud-content.com" in url and method == "GET":
            if "Scanned+document+1.pdf" in url:
                return ResponseMock({}, raw=open(".gitignore", "rb"))

        # Find My iPhone
        if "fmi" in url and method == "POST":
            return ResponseMock(FMI_FAMILY_WORKING)

        return None


class PyiCloudServiceMock(base.PyiCloudService):
    """Mocked PyiCloudService."""

    def __init__(
        self,
        apple_id,
        password=None,
        cookie_directory=None,
        verify=True,
        client_id=None,
        with_family=True,
        china_mainland=False,
    ):
        """Set up pyicloud service mock."""
        base.PyiCloudSession = PyiCloudSessionMock
        base.PyiCloudService.__init__(
            self, apple_id, password, cookie_directory, verify, client_id, with_family, china_mainland
        )
