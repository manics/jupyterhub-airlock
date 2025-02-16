import pytest
from uuid import uuid4


@pytest.fixture
def egress_id():
    return str(uuid4())
