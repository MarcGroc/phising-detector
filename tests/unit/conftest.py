import pytest


@pytest.fixture(scope="session")
def sample_session_fixture():
    """Sample pytest fixture for session scope."""
    return {"foo": "bar"}


@pytest.fixture(scope="module")
def sample_module_fixture():
    """Sample module pytest fixture for module scope."""
    return {"foo": "bar"}


@pytest.fixture()
def sample_fixture():
    """Sample pytest fixture available to all tests."""
    return {"foo": "bar"}
