import mock
import wifiphisher.common.firewall as firewall


@mock.patch("wifiphisher.common.firewall.subprocess.Popen")
def test_run_command_no_error(popen):
    """
    Test run_command which results in no errors
    """
    popen.return_value.communicate.return_value = (None, "")

    command = "ls -l".split()

    assert firewall.run_command(command) == (True, None)


@mock.patch("wifiphisher.common.firewall.subprocess.Popen")
def test_run_command_error(popen):
    """
    Test run_command which results in an errors
    """
    error_message = "SOME ERROR"
    popen.return_value.communicate.return_value = (None, error_message)

    command = "ls -l".split()

    assert firewall.run_command(command) == (False, error_message)


@mock.patch("wifiphisher.common.firewall.subprocess.Popen")
def test_clear_rules_no_error(popen):
    """
    Test clear_rules which results in no errors
    """
    popen.return_value.communicate.return_value = (None, "")

    assert firewall.clear_rules() == (True, None)


@mock.patch("wifiphisher.common.firewall.subprocess.Popen")
def test_clear_rules_error(popen):
    """
    Test clear_rules which results in an error
    """
    error_message = "ERROR"
    popen.return_value.communicate.return_value = (None, error_message)

    assert firewall.clear_rules() == (False, error_message)


@mock.patch("wifiphisher.common.firewall.subprocess.Popen")
def test_redirect_to_localhost_no_error(popen):
    """
    Test redirect_to_localhost which results in no error
    """
    popen.return_value.communicate.return_value = (None, "")

    assert firewall.redirect_to_localhost() == (True, None)


@mock.patch("wifiphisher.common.firewall.subprocess.Popen")
def test_redirect_to_localhost_error(popen):
    """
    Test redirect_to_localhost which results in an error
    """
    error_message = "ERROR"
    popen.return_value.communicate.return_value = (None, error_message)

    assert firewall.redirect_to_localhost() == (False, error_message)


@mock.patch("wifiphisher.common.firewall.subprocess.Popen")
def test_enable_internet_no_error(popen):
    """
    Test enable_internet which results in no error
    """
    popen.return_value.communicate.return_value = (None, "")

    assert firewall.enable_internet("wlan0", "eth0") == (True, None)


@mock.patch("wifiphisher.common.firewall.subprocess.Popen")
def test_enable_internet_error(popen):
    """
    Test enable_internet which results in an error
    """
    error_message = "ERROR"
    popen.return_value.communicate.return_value = (None, error_message)

    assert firewall.enable_internet("wlan0", "eth0") == (False, error_message)
