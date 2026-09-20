import atsq


def test_version() -> None:
    assert atsq.__version__


def test_public_exports_include_dialect_additions() -> None:
    assert "bans" in atsq.ALL_EVENTS
    assert atsq.BanUpdateOp.ADD == "add"
