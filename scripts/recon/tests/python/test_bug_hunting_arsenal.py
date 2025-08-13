import pytest
from unittest.mock import patch, MagicMock
from bug_hunting_arsenal import BugHuntingArsenal, main
import argparse
import sys
import io

@pytest.fixture
def default_args():
    """Fixture for default arguments."""
    return argparse.Namespace(
        target="example.com",
        output="reports/test_run/bug_hunting_arsenal",
        json=False,
        verbose=False,
        no_color=False,
        timeout=30,
        threads=10,
        dry_run=False,
        banner=False,
    )

def test_argument_parsing():
    """Test argument parsing."""
    parser = argparse.ArgumentParser(description="Bug Hunting Arsenal")
    parser.add_argument("-t", "--target", required=True, help="Target domain")
    with patch.object(sys, 'argv', ['bug_hunting_arsenal.py', '-t', 'example.com']):
        args = parser.parse_args(['-t', 'example.com'])
        assert args.target == "example.com"

@pytest.mark.asyncio
async def test_dry_run(default_args):
    """Test dry run functionality."""
    default_args.dry_run = True
    arsenal = BugHuntingArsenal(default_args)
    
    with patch.object(arsenal.logger, 'info') as mock_log_info:
        await arsenal.run_full_arsenal()
        mock_log_info.assert_any_call("[DRY RUN] Would perform all actions.")

def test_banner():
    """Test the banner output."""
    with patch.object(sys, 'stdout', new_callable=io.StringIO) as mock_stdout:
        with pytest.raises(SystemExit):
            with patch.object(sys, 'argv', ['bug_hunting_arsenal.py', '--banner']):
                main()
    
    assert "KDAIRATCHI SECURITY TOOLKIT" in mock_stdout.getvalue()
