import mock
from wifiphisher.common.dependencies import (Result,
                                             is_all_dependencies_installed)


@mock.patch(
    "wifiphisher.common.dependencies.find_executable",
    spec=True,
    return_value=True)
def test_is_all_dependencies_installed_all_installed(_):
    """Test function when all dependecies are installed."""
    assert is_all_dependencies_installed() == Result(status=True, missing=[])


@mock.patch(
    "wifiphisher.common.dependencies.find_executable",
    spec=True,
    return_value=None)
def test_is_all_dependencies_installed_all_not_installed(_):
    """Test function when all not dependecies are installed."""
    assert is_all_dependencies_installed() == Result(
        status=False, missing=["dnsmasq", "roguehostapd"])
