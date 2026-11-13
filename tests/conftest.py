from __future__ import annotations

import pytest

from wisebreak import config as config_mod
from wisebreak.db import Database


@pytest.fixture
def tmp_config(tmp_path):
    cfg = config_mod.load(None)
    return cfg.with_data_dir(tmp_path / "data")


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "wb.db")
    yield database
    database.close()
