#!/usr/bin/env python3
"""
test_bug_hunting_arsenal.py - Unit tests for bug_hunting_arsenal.py
Part of Security Research Tools
"""

import unittest
import asyncio
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock
import sys
import os

# Add the parent directory to the path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from bug_hunting_arsenal import BugHuntingArsenal


class TestBugHuntingArsenal(unittest.TestCase):
    """Unit tests for BugHuntingArsenal class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.arsenal = BugHuntingArsenal()
        self.test_domain = "example.com"
        self.temp_dir = Path(tempfile.mkdtemp())
        self.arsenal.output_dir = self.temp_dir
        self.arsenal.target_domain = self.test_domain
    
    def tearDown(self):
        """Clean up test fixtures"""
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
    
    def test_init(self):
        """Test initialization"""
        self.assertEqual(self.arsenal.name, "bug_hunting_arsenal")
        self.assertEqual(self.arsenal.version, "3.0.0")
        self.assertIsInstance(self.arsenal.subdomains, set)
        self.assertIsInstance(self.arsenal.urls, set)
        self.assertIsInstance(self.arsenal.stats, dict)
    
    def test_check_tool(self):
        """Test tool availability checking"""
        # Mock a tool that exists
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = None
            result = self.arsenal._check_tool('ls')
            self.assertTrue(result)
        
        # Mock a tool that doesn't exist
        with patch('subprocess.run', side_effect=FileNotFoundError):
            result = self.arsenal._check_tool('nonexistent_tool')
            self.assertFalse(result)
    
    def test_run_command_safe_invalid_input(self):
        """Test safe command execution with invalid input"""
        async def test_invalid_command():
            # Test with empty command
            result = await self.arsenal._run_command_safe([])
            self.assertEqual(result, "")
            
            # Test with invalid command format
            result = await self.arsenal._run_command_safe([123, "invalid"])
            self.assertEqual(result, "")
        
        asyncio.run(test_invalid_command())
    
    def test_run_command_safe_unavailable_tool(self):
        """Test safe command execution with unavailable tool"""
        async def test_unavailable_tool():
            # Set tool as unavailable
            self.arsenal.available_tools['nonexistent'] = False
            result = await self.arsenal._run_command_safe(['nonexistent', '--help'])
            self.assertEqual(result, "")
        
        asyncio.run(test_unavailable_tool())
    
    @patch('aiofiles.open')
    def test_read_file_lines(self, mock_open):
        """Test file reading functionality"""
        async def test_read():
            # Mock file content
            mock_file = AsyncMock()
            mock_file.read.return_value = "line1\nline2\n\nline3\n"
            mock_open.return_value.__aenter__.return_value = mock_file
            
            test_file = self.temp_dir / "test.txt"
            result = await self.arsenal._read_file_lines(test_file)
            
            self.assertEqual(result, ["line1", "line2", "line3"])
        
        asyncio.run(test_read())
    
    def test_subdomain_enumeration_setup(self):
        """Test subdomain enumeration setup"""
        async def test_setup():
            # Mock available tools
            self.arsenal.available_tools = {
                'subfinder': True,
                'assetfinder': True,
                'amass': True
            }
            
            # Mock the command execution to avoid actual tool calls
            with patch.object(self.arsenal, '_run_command_safe', return_value=""):
                with patch('aiohttp.ClientSession'):
                    await self.arsenal.subdomain_enumeration()
                    
                    # Check that stats were updated
                    self.assertIn('subdomains_found', self.arsenal.stats)
        
        asyncio.run(test_setup())
    
    def test_probe_alive_hosts_no_subdomains(self):
        """Test probing alive hosts with no subdomains"""
        async def test_no_subdomains():
            # Ensure no subdomains
            self.arsenal.subdomains = set()
            
            # Mock logger to capture warnings
            with patch.object(self.arsenal, 'logger', create=True) as mock_logger:
                mock_logger.warning = MagicMock()
                
                await self.arsenal.probe_alive_hosts()
                mock_logger.warning.assert_called_with("No subdomains to probe")
        
        # Initialize logger for test
        from lib.kdai_python import KdaiLogger
        self.arsenal.logger = KdaiLogger("test")
        
        asyncio.run(test_no_subdomains())
    
    def test_url_discovery_no_urls(self):
        """Test URL discovery with no alive hosts"""
        async def test_no_urls():
            # Ensure no URLs
            self.arsenal.urls = set()
            
            # Mock logger to capture warnings
            with patch.object(self.arsenal, 'logger', create=True) as mock_logger:
                mock_logger.warning = MagicMock()
                
                await self.arsenal.url_discovery()
                mock_logger.warning.assert_called_with("No alive hosts to discover URLs from")
        
        # Initialize logger for test
        from lib.kdai_python import KdaiLogger
        self.arsenal.logger = KdaiLogger("test")
        
        asyncio.run(test_no_urls())
    
    def test_technology_detection_setup(self):
        """Test technology detection setup"""
        async def test_tech_detection():
            # Add some test URLs
            self.arsenal.urls = {"https://example.com", "https://test.example.com"}
            self.arsenal.available_tools['whatweb'] = True
            
            # Mock command execution
            with patch.object(self.arsenal, '_run_command_safe', return_value="Web Server: nginx"):
                with patch.object(self.arsenal, 'logger', create=True) as mock_logger:
                    mock_logger.info = MagicMock()
                    mock_logger.success = MagicMock()
                    mock_logger.debug = MagicMock()
                    
                    await self.arsenal.technology_detection()
                    
                    # Check that technologies were detected
                    self.assertGreater(len(self.arsenal.technologies), 0)
        
        asyncio.run(test_tech_detection())
    
    def test_vulnerability_scanning_no_urls(self):
        """Test vulnerability scanning with no URLs"""
        async def test_no_urls():
            # Ensure no URLs
            self.arsenal.urls = set()
            
            # Mock logger to capture warnings
            with patch.object(self.arsenal, 'logger', create=True) as mock_logger:
                mock_logger.warning = MagicMock()
                
                await self.arsenal.vulnerability_scanning()
                mock_logger.warning.assert_called_with("No URLs for vulnerability scanning")
        
        # Initialize logger for test
        from lib.kdai_python import KdaiLogger
        self.arsenal.logger = KdaiLogger("test")
        
        asyncio.run(test_no_urls())
    
    def test_parameter_mining_no_data(self):
        """Test parameter mining with no crawled data"""
        async def test_no_data():
            # Ensure no crawled data
            self.arsenal.crawled_data = {}
            
            # Mock logger to capture warnings
            with patch.object(self.arsenal, 'logger', create=True) as mock_logger:
                mock_logger.warning = MagicMock()
                
                await self.arsenal.parameter_mining()
                mock_logger.warning.assert_called_with("No crawled data for parameter mining")
        
        # Initialize logger for test
        from lib.kdai_python import KdaiLogger
        self.arsenal.logger = KdaiLogger("test")
        
        asyncio.run(test_no_data())
    
    def test_parameter_mining_with_data(self):
        """Test parameter mining with sample data"""
        async def test_with_data():
            # Add sample crawled data
            self.arsenal.crawled_data = {
                "https://example.com": {
                    "markdown": 'name="username" name="password" ?id=123&page=1 "user_id":456'
                }
            }
            
            # Mock file manager
            mock_file_manager = MagicMock()
            self.arsenal.file_manager = mock_file_manager
            
            # Mock logger
            with patch.object(self.arsenal, 'logger', create=True) as mock_logger:
                mock_logger.info = MagicMock()
                mock_logger.success = MagicMock()
                
                await self.arsenal.parameter_mining()
                
                # Verify logger was called
                mock_logger.success.assert_called()
        
        # Initialize logger for test
        from lib.kdai_python import KdaiLogger
        self.arsenal.logger = KdaiLogger("test")
        
        asyncio.run(test_with_data())
    
    def test_generate_html_report(self):
        """Test HTML report generation"""
        # Create sample summary data
        summary = {
            'target': 'example.com',
            'timestamp': '2024-01-01T00:00:00',
            'statistics': {
                'subdomains_found': 5,
                'urls_discovered': 10,
                'endpoints_found': 15,
                'pages_crawled': 3,
                'technologies_detected': 2,
                'vulnerabilities_found': 1,
                'tools_used': ['subfinder', 'httpx'],
                'duration': 123.45
            },
            'subdomains': ['sub1.example.com', 'sub2.example.com'],
            'urls': ['https://example.com', 'https://sub1.example.com'],
            'endpoints': ['https://example.com/api'],
            'technologies': {'https://example.com': 'nginx'},
            'vulnerabilities': [{'finding': 'Test vulnerability'}]
        }
        
        html = self.arsenal._generate_html_report(summary)
        
        # Basic checks for HTML content
        self.assertIn('<!DOCTYPE html>', html)
        self.assertIn('Bug Hunting Arsenal Report', html)
        self.assertIn('example.com', html)
        self.assertIn('5', html)  # subdomains count
        self.assertIn('10', html)  # urls count
    
    def test_run_method_invalid_domain(self):
        """Test run method with invalid domain"""
        # Test with invalid domain
        result = self.arsenal.run(['-d', 'invalid..domain'])
        self.assertEqual(result, 2)  # EXIT_MISUSE
    
    def test_run_method_missing_domain(self):
        """Test run method with missing domain"""
        # Test without domain argument
        with patch('sys.stderr'):  # Suppress error output
            result = self.arsenal.run([])
            self.assertEqual(result, 2)  # EXIT_MISUSE


class TestKdaiValidator(unittest.TestCase):
    """Unit tests for KdaiValidator"""
    
    def setUp(self):
        from lib.kdai_python import KdaiValidator
        self.validator = KdaiValidator
    
    def test_domain_validation(self):
        """Test domain validation"""
        # Valid domains
        self.assertTrue(self.validator.domain("example.com"))
        self.assertTrue(self.validator.domain("sub.example.com"))
        self.assertTrue(self.validator.domain("test-domain.org"))
        self.assertTrue(self.validator.domain("a.co"))
        
        # Invalid domains
        self.assertFalse(self.validator.domain(""))
        self.assertFalse(self.validator.domain("invalid..domain"))
        self.assertFalse(self.validator.domain(".example.com"))
        self.assertFalse(self.validator.domain("example."))
        self.assertFalse(self.validator.domain("ex ample.com"))
    
    def test_url_validation(self):
        """Test URL validation"""
        # Valid URLs
        self.assertTrue(self.validator.url("https://example.com"))
        self.assertTrue(self.validator.url("http://test.com/path"))
        self.assertTrue(self.validator.url("https://sub.example.com/api?param=value"))
        
        # Invalid URLs
        self.assertFalse(self.validator.url(""))
        self.assertFalse(self.validator.url("ftp://example.com"))
        self.assertFalse(self.validator.url("example.com"))
        self.assertFalse(self.validator.url("https://"))
    
    def test_ip_validation(self):
        """Test IP address validation"""
        # Valid IPs
        self.assertTrue(self.validator.ip_address("192.168.1.1"))
        self.assertTrue(self.validator.ip_address("127.0.0.1"))
        self.assertTrue(self.validator.ip_address("255.255.255.255"))
        self.assertTrue(self.validator.ip_address("0.0.0.0"))
        
        # Invalid IPs
        self.assertFalse(self.validator.ip_address(""))
        self.assertFalse(self.validator.ip_address("256.1.1.1"))
        self.assertFalse(self.validator.ip_address("192.168.1"))
        self.assertFalse(self.validator.ip_address("192.168.1.1.1"))
        self.assertFalse(self.validator.ip_address("192.168.1.a"))
    
    def test_port_validation(self):
        """Test port validation"""
        # Valid ports
        self.assertTrue(self.validator.port(80))
        self.assertTrue(self.validator.port("443"))
        self.assertTrue(self.validator.port(65535))
        self.assertTrue(self.validator.port("1"))
        
        # Invalid ports
        self.assertFalse(self.validator.port(0))
        self.assertFalse(self.validator.port(65536))
        self.assertFalse(self.validator.port(""))
        self.assertFalse(self.validator.port("abc"))
        self.assertFalse(self.validator.port(-1))


if __name__ == '__main__':
    # Create test directories if they don't exist
    test_dir = Path(__file__).parent
    test_dir.mkdir(exist_ok=True)
    
    # Run tests
    unittest.main(verbosity=2)