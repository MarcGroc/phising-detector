import pytest
@pytest.fixture()
def sample_fixture():
    """Sample pytest fixture available to all tests."""
    return {"foo": "bar"}