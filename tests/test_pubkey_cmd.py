import pytest

from application_client.ironfish_command_sender import IronfishCommandSender, Errors
from application_client.ironfish_response_unpacker import unpack_get_public_key_response
from ragger.bip import calculate_public_key_and_chaincode, CurveChoice
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavInsID, NavIns
from utils import ROOT_SCREENSHOT_PATH


# In this test we check that the GET_PUBLIC_KEY works in non-confirmation mode
def test_get_public_key_no_confirm(backend):
    for path in ["m/44'/1'/0'/0/0", "m/44'/1'/0/0/0", "m/44'/1'/911'/0/0", "m/44'/1'/255/255/255", "m/44'/1'/2147483647/0/0/0/0/0/0/0"]:
        client = IronfishCommandSender(backend)
        response = client.get_public_key(path=path).data
        _, public_key, _, _ = unpack_get_public_key_response(response)

        ref_public_key, _ = calculate_public_key_and_chaincode(CurveChoice.Secp256k1, path=path)
        assert public_key.hex() == ref_public_key


# In this test we check that the GET_PUBLIC_KEY works in confirmation mode
def test_get_public_key_confirm_accepted(backend, scenario_navigator):
    client = IronfishCommandSender(backend)
    path = "m/44'/1'/0'/0/0"
    
    with client.get_public_key_with_confirmation(path=path):
        scenario_navigator.address_review_approve()
        
    response = client.get_async_response().data
    _, public_key, _, _ = unpack_get_public_key_response(response)

    ref_public_key, _ = calculate_public_key_and_chaincode(CurveChoice.Secp256k1, path=path)
    assert public_key.hex() == ref_public_key


# In this test we check that the GET_PUBLIC_KEY in confirmation mode replies an error if the user refuses
def test_get_public_key_confirm_refused(backend, scenario_navigator):
    client = IronfishCommandSender(backend)
    path = "m/44'/1'/0'/0/0"

    with pytest.raises(ExceptionRAPDU) as e:
        with client.get_public_key_with_confirmation(path=path):
            scenario_navigator.address_review_reject()

    # Assert that we have received a refusal
    assert e.value.status == Errors.SW_DENY
    assert len(e.value.data) == 0
