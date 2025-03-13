"""Unit tests for hooks/services.py."""

from unittest import mock

import services


@mock.patch("services.status_set")
@mock.patch("services.subprocess.call")
@mock.patch("services.nrpe_helpers.has_netlinks_error")
@mock.patch("services.nrpe_utils.has_consumer")
@mock.patch("services.nrpe_helpers.is_cis_misconfigured")
def test_update_status_active(
    mock_is_cis_misconfigured,
    mock_has_consumer,
    mock_has_netlinks_error,
    mock_subprocess_call,
    mock_status_set,
):
    mock_is_cis_misconfigured.return_value = (False, "")
    mock_has_consumer.return_value = True
    mock_has_netlinks_error.return_value = False
    mock_subprocess_call.return_value = 0

    services.update_status()

    mock_status_set.assert_called_once_with("active", "Ready")


@mock.patch("services.status_set")
@mock.patch("services.subprocess.call")
@mock.patch("services.nrpe_helpers.has_netlinks_error")
@mock.patch("services.nrpe_utils.has_consumer")
@mock.patch("services.nrpe_helpers.is_cis_misconfigured")
def test_update_status_cis_misconfigured(
    mock_is_cis_misconfigured,
    mock_has_consumer,
    mock_has_netlinks_error,
    mock_subprocess_call,
    mock_status_set,
):
    mock_is_cis_misconfigured.return_value = (True, "CIS MISCONFIGURED")
    mock_has_consumer.return_value = True
    mock_has_netlinks_error.return_value = False
    mock_subprocess_call.return_value = 0

    services.update_status()

    mock_status_set.assert_called_once_with("blocked", "CIS MISCONFIGURED")
