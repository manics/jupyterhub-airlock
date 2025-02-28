from uuid import uuid4

import pytest


def random_egress_component():
    return str(uuid4()).split("-")[0]


def random_egress_id():
    return str(uuid4()).replace("-", "/", 2)


@pytest.fixture
def egress_id():
    return random_egress_id()
