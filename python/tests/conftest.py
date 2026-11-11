import pytest

# A typical ARQC field 55 built from test values.
FIELD_55 = (
    "9F26081122334455667788"
    "9F270180"
    "9F100706010A03A00000"
    "9F370412345678"
    "9F36020001"
    "95050000008000"
    "9A03261111"
    "9C0100"
    "9F0206000000010000"
    "5F2A020566"
    "82023900"
    "9F1A020566"
    "9F3403420300"
)


@pytest.fixture
def field55():
    return FIELD_55
