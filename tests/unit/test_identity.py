import atsq

# Synthetic key; the derivation was checked live against a TS6 6.0.0-beta13.1 server.
PUBLIC_KEY = (
    "ME0DAgcAAgEgAiEAtestkeyForUnitTestsOnlyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
)


def test_ts3_uid_is_sha1_of_the_key_string() -> None:
    uid = atsq.ts3_uid_from_public_key(PUBLIC_KEY)
    assert uid == "UQHA9NHzAyLXMNUKvBhJTTPUQkw="
    assert len(uid) == 28


def test_ts6_uid_is_sha256_of_the_key_string() -> None:
    uid = atsq.ts6_uid_from_public_key(PUBLIC_KEY)
    assert uid == "q/Vu1dSlHpfSY28nKfcrUfo3PywHfuB5e7RPQQaY768="
    assert len(uid) == 44
