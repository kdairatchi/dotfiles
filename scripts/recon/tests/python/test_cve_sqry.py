import pytest
from unittest.mock import patch, MagicMock
from cve_sqry import CveSqryTool
import argparse
import sys
import io

@pytest.fixture
def default_args():
    """Fixture for default arguments."""
    return argparse.Namespace(
        targets=None,
        output="reports/test_run/cve-sqry",
        json=False,
        verbose=False,
        no_color=False,
        timeout=30,
        dry_run=False,
        banner=False,
        cve_id=None,
        product=None,
        cpe23=None,
    )

def test_argument_parsing():
    """Test argument parsing."""
    parser = argparse.ArgumentParser(description="CVE-SQRY Tool")
    parser.add_argument("-t", "--targets", nargs='+', help="List of targets for sqry search")
    args = parser.parse_args(['-t', 'example.com'])
    assert args.targets == ["example.com"]

@patch('cve_sqry.subprocess.run')
def test_sqry_search(mock_subprocess_run, default_args):
    """Test sqry search functionality."""
    default_args.targets = ["example.com"]
    mock_subprocess_run.return_value = MagicMock(stdout="1.1.1.1\n2.2.2.2", stderr="", returncode=0)
    tool = CveSqryTool(default_args)
    results = tool.handle_sqry_search()
    assert len(results) == 2
    assert results[0]['ip'] == "1.1.1.1"

@patch('cve_sqry.requests.get')
def test_cve_search(mock_requests_get, default_args):
    """Test CVE search functionality."""
    default_args.cve_id = "CVE-2025-8139"
    mock_requests_get.return_value = MagicMock(
        status_code=200,
        json=lambda: {"cve": "CVE-2025-8139", "summary": "A test CVE."}
    )
    tool = CveSqryTool(default_args)
    results = tool.handle_cve_search()
    assert len(results) == 1
    assert results[0]['cve'] == "CVE-2025-8139"

def test_banner():
    """Test the banner output."""
    with patch.object(sys, 'stdout', new_callable=io.StringIO) as mock_stdout:
        with pytest.raises(SystemExit):
            with patch.object(sys, 'argv', ['cve-sqry.py', '--banner']):
                from cve_sqry import main
                main()
    
    assert "KDAIRATCHI SECURITY TOOLKIT" in mock_stdout.getvalue()
