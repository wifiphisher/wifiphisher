import mock
from subprocess import CalledProcessError
from wifiphisher.common.dependencies import (is_installed, Result,
                                             is_all_dependencies_installed)


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
    "wifiphisher.common.dependencies.check_call",
    spec=True,
    return_value=True)
def test_is_all_dependencies_installed_all_installed(_):
    """Test function when all dependecies are installed."""
    assert is_all_dependencies_installed() == Result(status=True, missing=[])


@mock.patch(
    "wifiphisher.common.dependencies.check_call",
    spec=True,
    side_effect=CalledProcessError(1, "cmd", None))
def test_is_all_dependencies_installed_all_not_installed(_):
    """Test function when all not dependecies are installed."""
    assert is_all_dependencies_installed() == Result(
        status=False, missing=["dnsmasq", "roguehostapd"])
