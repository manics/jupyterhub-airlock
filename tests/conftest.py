import pytest
from uuid import uuid4


def random_egress_id():
    return str(uuid4()).replace("-", "/", 1)


@pytest.fixture
def egress_id():
    return random_egress_id()
