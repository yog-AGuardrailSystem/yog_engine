"""The reference interpreter's IPv6 parser against Python's ipaddress module (an independent implementation)."""
import ipaddress
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "reference"))
import yog_ref  # noqa: E402


def stdlib(text):
    if "%" in text or "/" in text or text.strip() != text:
        return None
    try:
        return int(ipaddress.IPv6Address(text))
    except ValueError:
        return None


def test_every_address_form_the_standard_library_knows():
    for text in ["::", "::1", "1::", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7::", "::2:3:4:5:6:7:8", "1::8", "ffff::", "FFFF::AbCd",
                 "::ffff:1.2.3.4", "64:ff9b::192.0.2.33", "1:2:3:4:5:6:1.2.3.4", "2001:db8::1", "0:0:0:0:0:0:0:0"]:
        assert yog_ref._ipv6(text) == stdlib(text) is not None, text


def test_random_strings_agree_with_the_standard_library():
    rng = random.Random(7)
    pieces = ["0", "1", "a", "F", "ff", "1234", "12345", ":", ":", "::", "::", ".", "1.2.3.4", "01.2.3.4", "g", "%", " ", "-"]
    agree = valid = 0
    for _ in range(20000):
        text = "".join(rng.choice(pieces) for _ in range(rng.randint(1, 12)))
        assert yog_ref._ipv6(text) == stdlib(text), repr(text)
        agree += 1
        valid += stdlib(text) is not None
    assert agree == 20000 and valid > 200            # the generator does produce valid addresses, not only garbage


def test_cidr_matches_the_standard_library_for_random_networks():
    rng = random.Random(11)
    for _ in range(3000):
        address = ipaddress.IPv6Address(rng.getrandbits(128))
        bits = rng.randint(0, 128)
        network = ipaddress.IPv6Network((address, bits), strict=False)
        inside = ipaddress.IPv6Address(int(network.network_address) | rng.getrandbits(128 - bits) if bits < 128 else int(address))
        other = ipaddress.IPv6Address(rng.getrandbits(128))
        for candidate in (inside, other):
            assert yog_ref._cidr(str(candidate), f"{network.network_address}/{bits}") == (candidate in network)
