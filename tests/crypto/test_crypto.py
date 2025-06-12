# pyvider/rpcplugin/tests/test_certificate_crypto.py

import pytest


from tests.fixtures import *


@pytest.mark.asyncio
async def test_certificate_verification(client_cert, server_cert) -> None:
    """Ensure certificate can verify another certificate."""
    assert client_cert.verify_trust(server_cert) is False, (
        "Self-verification should fail"
    )
