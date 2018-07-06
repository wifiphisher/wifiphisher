import mock
from subprocess import CalledProcessError
from wifiphisher.common.dependencies import (is_installed,
                                             find_missing_dependencies)


@mock.patch(
    "wifiphisher.common.dependencies.check_call", spec=True, return_value=True)
def test_is_installed_installed_true(_):
    """Test function when an application is installed."""
    assert is_installed("myApplication")


@mock.patch(
    "wifiphisher.common.dependencies.check_call",
    spec=True,
    side_effect=CalledProcessError(1, "cmd", None))
def test_is_installed_installed_false(_):
    """Test function when an application is not installed."""
    assert not is_installed("noApplication")


@mock.patch(
    "wifiphisher.common.dependencies.check_call", spec=True, return_value=True)
def test_find_missing_dependencies_all_installed(_):
    """Test function when all dependecies are installed."""
    assert find_missing_dependencies() == []


@mock.patch(
    "wifiphisher.common.dependencies.check_call",
    spec=True,
    side_effect=CalledProcessError(1, "cmd", None))
def test_find_missing_dependencies_all_not_installed(_):
    """Test function when all not dependecies are installed."""
    assert find_missing_dependencies()[:2] == ["dnsmasq", "iptables"]
