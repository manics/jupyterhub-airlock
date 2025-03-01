from uuid import uuid4

import pytest


def random_egress_id():
    return str(uuid4()).replace("-", "/", 1)


@pytest.fixture
def egress_id():
    return random_egress_id()
