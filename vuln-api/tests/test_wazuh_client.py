import pytest
from unittest.mock import patch, MagicMock
from app import wazuh_client
import requests

def test_get_auth_header():
    headers = wazuh_client.get_auth_header("user", "password")
    assert "Authorization" in headers
    assert headers["Authorization"].startswith("Basic ")
    assert headers["Content-Type"] == "application/json"

@patch("app.wazuh_client.requests.post")
@patch("app.wazuh_client.requests.delete")
def test_fetch_all_vulns_success(mock_delete, mock_post):
    # Simulate two pages of results
    mock_post_page1 = MagicMock()
    mock_post_page1.json.return_value = {
        "_scroll_id": "scroll_123",
        "hits": {
            "hits": [
                {"_source": {"vuln_id": "1"}},
                {"_source": {"vuln_id": "2"}}
            ]
        }
    }
    
    mock_post_page2 = MagicMock()
    mock_post_page2.json.return_value = {
        "_scroll_id": "scroll_123",
        "hits": {
            "hits": [
                {"_source": {"vuln_id": "3"}}
            ]
        }
    }

    # Third call returns empty hits to break the loop
    mock_post_page3 = MagicMock()
    mock_post_page3.json.return_value = {
        "_scroll_id": "scroll_123",
        "hits": {
            "hits": []
        }
    }

    # Assign side_effect for multiple calls
    mock_post.side_effect = [mock_post_page1, mock_post_page2, mock_post_page3]

    results = wazuh_client.fetch_all_vulns("http://localhost", "user", "pass")
    
    # Assertions
    assert len(results) == 3
    assert results == [{"vuln_id": "1"}, {"vuln_id": "2"}, {"vuln_id": "3"}]
    
    # Verify post was called 3 times (1 initial + 2 scroll calls)
    assert mock_post.call_count == 3
    
    # Verify delete was called once in the finally block
    mock_delete.assert_called_once()
    delete_kwargs = mock_delete.call_args[1]
    assert delete_kwargs["json"] == {"scroll_id": ["scroll_123"]}

@patch("app.wazuh_client.requests.post")
@patch("app.wazuh_client.requests.delete")
def test_fetch_all_vulns_delete_exception(mock_delete, mock_post):
    # Simulate one page of results (empty)
    mock_post_page1 = MagicMock()
    mock_post_page1.json.return_value = {
        "_scroll_id": "scroll_123",
        "hits": {"hits": []}
    }
    mock_post.side_effect = [mock_post_page1]

    # Simulate exception during delete
    mock_delete.side_effect = Exception("Delete failed")

    # Should not raise exception, but catch it
    results = wazuh_client.fetch_all_vulns("http://localhost", "user", "pass")
    assert len(results) == 0
    mock_delete.assert_called_once()

@patch("app.wazuh_client.requests.post")
def test_fetch_all_vulns_post_exception(mock_post):
    # Simulate a requests.exceptions.HTTPError
    mock_post.side_effect = requests.exceptions.HTTPError("Bad Request")

    with pytest.raises(requests.exceptions.HTTPError):
        wazuh_client.fetch_all_vulns("http://localhost", "user", "pass")

@patch("app.wazuh_client.requests.get")
def test_test_connection_success(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "OK"
    mock_get.return_value = mock_resp

    result = wazuh_client.test_connection("http://localhost", "user", "pass")
    assert result is True

@patch("app.wazuh_client.requests.get")
def test_test_connection_failure(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_resp.text = "Unauthorized"
    mock_get.return_value = mock_resp

    result = wazuh_client.test_connection("http://localhost", "user", "pass")
    assert result is False

@patch("app.wazuh_client.requests.get")
def test_test_connection_exception(mock_get):
    mock_get.side_effect = requests.exceptions.ConnectionError("Connection Refused")
    
    result = wazuh_client.test_connection("http://localhost", "user", "pass")
    assert result is False
