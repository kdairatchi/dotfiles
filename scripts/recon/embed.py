#!/usr/bin/env python3
"""
Bug Hunting Arsenal Menu System
Enhanced interactive menu for security reconnaissance tools
"""

import os
import sys
import time
import json
import asyncio
import subprocess
import importlib.util
import signal
import shutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from colorama import Fore, Style, Back, init
from prompt_toolkit import prompt
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.completion import PathCompleter, WordCompleter
from prompt_toolkit.styles import Style as PromptStyle

# Initialize colorama
init(autoreset=True)

# Custom prompt style
custom_style = PromptStyle.from_dict({
    'prompt': 'ansicyan bold',
    'input': 'ansiwhite',
})

class BugHuntingMenu:
    """Enhanced menu system for Bug Hunting Arsenal"""
    
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.arsenal_script = self.project_root / "bug_hunting_arsenal.py"
        self.requirements_file = self.project_root / "requirements.txt"
        self.venv_dir = self.project_root / "venv"
        self.reports_dir = self.project_root / "reports"
        self.tools_dir = self.project_root.parent.parent / "tools"
        
        # Colors and styling
        self.colors = {
            'primary': Fore.CYAN,
            'secondary': Fore.BLUE,
            'success': Fore.GREEN,
            'warning': Fore.YELLOW,
            'error': Fore.RED,
            'info': Fore.MAGENTA,
            'reset': Style.RESET_ALL,
            'bold': Style.BRIGHT,
            'dim': Style.DIM
        }
        
        # Menu options
        self.main_menu_options = [
            ("1", "🔍 Run Bug Hunting Arsenal", self.run_arsenal),
            ("2", "🛠️  Setup & Installation", self.setup_menu),
            ("3", "📊 View Reports", self.reports_menu),
            ("4", "🔧 Tool Management", self.tools_menu),
            ("5", "📚 Documentation", self.documentation_menu),
            ("6", "⚙️  Configuration", self.config_menu),
            ("0", "🚪 Exit", self.exit_program)
        ]
        
        self.setup_options = [
            ("1", "🐍 Python Environment", self.setup_python_env),
            ("2", "📦 Install Dependencies", self.install_dependencies),
            ("3", "🔨 Install Security Tools", self.install_security_tools),
            ("4", "✅ Run Tests", self.run_tests),
            ("5", "🔍 Check System Status", self.check_system_status),
            ("0", "⬅️  Back to Main Menu", None)
        ]
        
        self.tools_options = [
            ("1", "🔍 Subdomain Enumeration", self.subdomain_tools),
            ("2", "🌐 URL Discovery", self.url_discovery_tools),
            ("3", "🔒 Vulnerability Scanning", self.vuln_scanning_tools),
            ("4", "📱 Technology Detection", self.tech_detection_tools),
            ("5", "📄 Payload Generation", self.payload_tools),
            ("0", "⬅️  Back to Main Menu", None)
        ]

    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')

    def print_banner(self):
        """Print the main banner"""
        banner = f"""
{self.colors['primary']}{'='*70}
{self.colors['bold']}  🛡️  KDAIRATCHI SECURITY TOOLKIT  🛡️
{self.colors['secondary']}  Bug Hunting Arsenal - Interactive Menu
{self.colors['info']}  "real never lies." | github.com/kdairatchi/dotfiles
{self.colors['primary']}{'='*70}{self.colors['reset']}
"""
        print(banner)

    def print_status_bar(self, message: str, status: str = "INFO"):
        """Print a status bar with message"""
        status_colors = {
            "INFO": self.colors['info'],
            "SUCCESS": self.colors['success'],
            "WARNING": self.colors['warning'],
            "ERROR": self.colors['error']
        }
        
        color = status_colors.get(status, self.colors['info'])
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{color}[{timestamp}] {status}: {message}{self.colors['reset']}")

    def print_menu(self, title: str, options: List[Tuple[str, str, Optional[callable]]], 
                   subtitle: str = ""):
        """Print a formatted menu"""
        print(f"\n{self.colors['primary']}{'='*50}")
        print(f"{self.colors['bold']}{title}")
        if subtitle:
            print(f"{self.colors['secondary']}{subtitle}")
        print(f"{self.colors['primary']}{'='*50}{self.colors['reset']}")
        
        for key, description, _ in options:
            print(f"{self.colors['warning']}[{key}]{self.colors['reset']} {description}")
        
        print(f"{self.colors['primary']}{'='*50}{self.colors['reset']}")

    def get_user_input(self, prompt_text: str, completer=None) -> str:
        """Get user input with optional completion"""
        try:
            if completer:
                return prompt(
                    HTML(f"<ansicyan>[?]</ansicyan> {prompt_text}"),
                    completer=completer,
                    style=custom_style
                ).strip()
            else:
                return prompt(
                    HTML(f"<ansicyan>[?]</ansicyan> {prompt_text}"),
                    style=custom_style
                ).strip()
        except KeyboardInterrupt:
            return ""

    def pause(self, message: str = "Press Enter to continue..."):
        """Pause execution and wait for user input"""
        try:
            self.get_user_input(message)
        except KeyboardInterrupt:
            pass

    def check_python_package(self, package: str) -> bool:
        """Check if a Python package is installed"""
        return importlib.util.find_spec(package) is not None

    def install_python_package(self, package: str) -> bool:
        """Install a Python package"""
        try:
            self.print_status_bar(f"Installing {package}...", "INFO")
            subprocess.check_call([
                sys.executable, '-m', 'pip', 'install', package
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.print_status_bar(f"{package} installed successfully", "SUCCESS")
            return True
        except subprocess.CalledProcessError:
            self.print_status_bar(f"Failed to install {package}", "ERROR")
            return False

    def run_arsenal(self):
        """Run the bug hunting arsenal"""
        self.clear_screen()
        self.print_banner()
        
        if not self.arsenal_script.exists():
            self.print_status_bar("Bug Hunting Arsenal script not found!", "ERROR")
            self.pause()
            return
        
        # Get target domain
        target = self.get_user_input("Enter target domain (e.g., example.com): ")
        if not target:
            self.print_status_bar("No target specified", "WARNING")
            self.pause()
            return
        
        # Get output directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_output = f"reports/{timestamp}_{target}"
        output = self.get_user_input(f"Output directory (Enter for {default_output}): ")
        if not output:
            output = default_output
        
        # Get additional options
        email = self.get_user_input("Email for EmailRep enrichment (optional): ")
        verbose = self.get_user_input("Enable verbose output? (y/N): ").lower() == 'y'
        json_output = self.get_user_input("Output JSON to stdout? (y/N): ").lower() == 'y'
        
        # Build command
        cmd = [sys.executable, str(self.arsenal_script), "-t", target, "-o", output]
        
        if email:
            cmd.extend(["--email", email])
        if verbose:
            cmd.append("-v")
        if json_output:
            cmd.append("--json")
        
        # Execute
        self.print_status_bar(f"Starting Bug Hunting Arsenal for {target}...", "INFO")
        print(f"\n{self.colors['info']}Command: {' '.join(cmd)}{self.colors['reset']}\n")
        
        try:
            result = subprocess.run(cmd, cwd=self.project_root)
            if result.returncode == 0:
                self.print_status_bar("Bug Hunting Arsenal completed successfully!", "SUCCESS")
            else:
                self.print_status_bar("Bug Hunting Arsenal failed", "ERROR")
        except KeyboardInterrupt:
            self.print_status_bar("Operation interrupted by user", "WARNING")
        except Exception as e:
            self.print_status_bar(f"Error: {e}", "ERROR")
        
        self.pause()

    def setup_python_env(self):
        """Setup Python virtual environment"""
        self.clear_screen()
        self.print_banner()
        self.print_status_bar("Setting up Python virtual environment...", "INFO")
        
        if self.venv_dir.exists():
            response = self.get_user_input(
                "Virtual environment already exists. Recreate? (y/N): "
            ).lower()
            if response != 'y':
                self.print_status_bar("Using existing virtual environment", "INFO")
                return
            shutil.rmtree(self.venv_dir)
        
        try:
            # Create virtual environment
            subprocess.check_call([
                sys.executable, '-m', 'venv', str(self.venv_dir)
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            self.print_status_bar("Virtual environment created successfully", "SUCCESS")
            
            # Install requirements if available
            if self.requirements_file.exists():
                self.print_status_bar("Installing requirements...", "INFO")
                pip_cmd = str(self.venv_dir / "bin" / "pip") if os.name != 'nt' else str(self.venv_dir / "Scripts" / "pip.exe")
                subprocess.check_call([
                    pip_cmd, "install", "-r", str(self.requirements_file)
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.print_status_bar("Requirements installed successfully", "SUCCESS")
            
        except subprocess.CalledProcessError as e:
            self.print_status_bar(f"Failed to setup environment: {e}", "ERROR")
        
        self.pause()

    def install_dependencies(self):
        """Install Python dependencies"""
        self.clear_screen()
        self.print_banner()
        
        if not self.requirements_file.exists():
            self.print_status_bar("requirements.txt not found!", "ERROR")
            self.pause()
            return
        
        required_packages = [
            "aiofiles", "aiohttp", "crawl4ai", "dnspython", 
            "python-whois", "requests", "beautifulsoup4", 
            "colorama", "urllib3", "lxml", "pyyaml"
        ]
        
        self.print_status_bar("Checking and installing dependencies...", "INFO")
        
        for package in required_packages:
            if not self.check_python_package(package):
                self.install_python_package(package)
            else:
                self.print_status_bar(f"{package} already installed", "SUCCESS")
        
        self.pause()

    def install_security_tools(self):
        """Install security tools"""
        self.clear_screen()
        self.print_banner()
        
        tools = [
            ("subfinder", "Subdomain enumeration"),
            ("httpx", "HTTP probing"),
            ("nuclei", "Vulnerability scanning"),
            ("nmap", "Network scanning"),
            ("whatweb", "Technology detection"),
            ("katana", "Web crawling"),
            ("waymore", "URL discovery")
        ]
        
        self.print_status_bar("Checking security tools...", "INFO")
        
        for tool, description in tools:
            if shutil.which(tool):
                self.print_status_bar(f"✓ {tool}: {description}", "SUCCESS")
            else:
                self.print_status_bar(f"✗ {tool}: {description} (not found)", "WARNING")
        
        self.print_status_bar("Use the setup script for automatic tool installation", "INFO")
        self.pause()

    def run_tests(self):
        """Run tests"""
        self.clear_screen()
        self.print_banner()
        
        test_dir = self.project_root / "tests"
        if not test_dir.exists():
            self.print_status_bar("Tests directory not found", "WARNING")
            self.pause()
            return
        
        self.print_status_bar("Running tests...", "INFO")
        
        try:
            result = subprocess.run([
                sys.executable, "-m", "pytest", str(test_dir), "-v"
            ], cwd=self.project_root)
            
            if result.returncode == 0:
                self.print_status_bar("All tests passed!", "SUCCESS")
            else:
                self.print_status_bar("Some tests failed", "WARNING")
        except Exception as e:
            self.print_status_bar(f"Error running tests: {e}", "ERROR")
        
        self.pause()

    def check_system_status(self):
        """Check system status"""
        self.clear_screen()
        self.print_banner()
        
        print(f"{self.colors['primary']}System Status Check{self.colors['reset']}\n")
        
        # Check Python
        python_version = sys.version.split()[0]
        print(f"{self.colors['success']}✓ Python: {python_version}{self.colors['reset']}")
        
        # Check virtual environment
        if self.venv_dir.exists():
            print(f"{self.colors['success']}✓ Virtual Environment: {self.venv_dir}{self.colors['reset']}")
        else:
            print(f"{self.colors['warning']}✗ Virtual Environment: Not found{self.colors['reset']}")
        
        # Check requirements
        if self.requirements_file.exists():
            print(f"{self.colors['success']}✓ Requirements: {self.requirements_file}{self.colors['reset']}")
        else:
            print(f"{self.colors['warning']}✗ Requirements: Not found{self.colors['reset']}")
        
        # Check arsenal script
        if self.arsenal_script.exists():
            print(f"{self.colors['success']}✓ Arsenal Script: {self.arsenal_script}{self.colors['reset']}")
        else:
            print(f"{self.colors['error']}✗ Arsenal Script: Not found{self.colors['reset']}")
        
        # Check reports directory
        if self.reports_dir.exists():
            print(f"{self.colors['success']}✓ Reports Directory: {self.reports_dir}{self.colors['reset']}")
        else:
            print(f"{self.colors['info']}ℹ Reports Directory: Will be created automatically{self.colors['reset']}")
        
        self.pause()

    def reports_menu(self):
        """Reports menu"""
        self.clear_screen()
        self.print_banner()
        
        if not self.reports_dir.exists():
            self.print_status_bar("No reports directory found", "INFO")
            self.pause()
            return
        
        reports = list(self.reports_dir.glob("*"))
        if not reports:
            self.print_status_bar("No reports found", "INFO")
            self.pause()
            return
        
        print(f"{self.colors['primary']}Available Reports{self.colors['reset']}\n")
        
        for i, report in enumerate(reports, 1):
            if report.is_dir():
                summary_file = report / "summary.json"
                if summary_file.exists():
                    try:
                        with open(summary_file) as f:
                            data = json.load(f)
                            target = data.get('targets', ['Unknown'])[0]
                            timestamp = data.get('timestamp', 'Unknown')
                            stats = data.get('stats', {})
                            subdomains = stats.get('subdomains_found', 0)
                            urls = stats.get('urls_discovered', 0)
                            
                        print(f"{self.colors['warning']}[{i}]{self.colors['reset']} {report.name}")
                        print(f"    Target: {target}")
                        print(f"    Subdomains: {subdomains}")
                        print(f"    URLs: {urls}")
                        print(f"    Date: {timestamp[:10]}")
                        print()
                    except:
                        print(f"{self.colors['warning']}[{i}]{self.colors['reset']} {report.name} (corrupted)")
                else:
                    print(f"{self.colors['warning']}[{i}]{self.colors['reset']} {report.name} (no summary)")
        
        self.pause()

    def tools_menu(self):
        """Tools management menu"""
        while True:
            self.clear_screen()
            self.print_banner()
            self.print_menu("Tool Management", self.tools_options)
            
            choice = self.get_user_input("Choose an option: ")
            
            if choice == "0":
                break
            elif choice == "1":
                self.subdomain_tools()
            elif choice == "2":
                self.url_discovery_tools()
            elif choice == "3":
                self.vuln_scanning_tools()
            elif choice == "4":
                self.tech_detection_tools()
            elif choice == "5":
                self.payload_tools()
            else:
                self.print_status_bar("Invalid option", "ERROR")
                self.pause()

    def subdomain_tools(self):
        """Subdomain enumeration tools"""
        self.clear_screen()
        self.print_banner()
        
        tools = [
            ("subfinder", "Fast subdomain enumeration"),
            ("assetfinder", "Find subdomains via various sources"),
            ("amass", "Comprehensive subdomain enumeration"),
            ("crt.sh", "Certificate transparency search")
        ]
        
        print(f"{self.colors['primary']}Subdomain Enumeration Tools{self.colors['reset']}\n")
        
        for tool, description in tools:
            if shutil.which(tool):
                print(f"{self.colors['success']}✓ {tool}: {description}{self.colors['reset']}")
            else:
                print(f"{self.colors['warning']}✗ {tool}: {description} (not installed){self.colors['reset']}")
        
        self.pause()

    def url_discovery_tools(self):
        """URL discovery tools"""
        self.clear_screen()
        self.print_banner()
        
        tools = [
            ("katana", "Fast web crawling"),
            ("waymore", "Archive.org URL discovery"),
            ("gau", "Get All URLs from various sources"),
            ("httpx", "HTTP probing and validation")
        ]
        
        print(f"{self.colors['primary']}URL Discovery Tools{self.colors['reset']}\n")
        
        for tool, description in tools:
            if shutil.which(tool):
                print(f"{self.colors['success']}✓ {tool}: {description}{self.colors['reset']}")
            else:
                print(f"{self.colors['warning']}✗ {tool}: {description} (not installed){self.colors['reset']}")
        
        self.pause()

    def vuln_scanning_tools(self):
        """Vulnerability scanning tools"""
        self.clear_screen()
        self.print_banner()
        
        tools = [
            ("nuclei", "Fast vulnerability scanner"),
            ("nmap", "Network security scanner"),
            ("sqlmap", "SQL injection scanner"),
            ("nikto", "Web server scanner")
        ]
        
        print(f"{self.colors['primary']}Vulnerability Scanning Tools{self.colors['reset']}\n")
        
        for tool, description in tools:
            if shutil.which(tool):
                print(f"{self.colors['success']}✓ {tool}: {description}{self.colors['reset']}")
            else:
                print(f"{self.colors['warning']}✗ {tool}: {description} (not installed){self.colors['reset']}")
        
        self.pause()

    def tech_detection_tools(self):
        """Technology detection tools"""
        self.clear_screen()
        self.print_banner()
        
        tools = [
            ("whatweb", "Web application fingerprinting"),
            ("wappalyzer", "Technology detection"),
            ("httpx", "HTTP technology detection")
        ]
        
        print(f"{self.colors['primary']}Technology Detection Tools{self.colors['reset']}\n")
        
        for tool, description in tools:
            if shutil.which(tool):
                print(f"{self.colors['success']}✓ {tool}: {description}{self.colors['reset']}")
            else:
                print(f"{self.colors['warning']}✗ {tool}: {description} (not installed){self.colors['reset']}")
        
        self.pause()

    def payload_tools(self):
        """Payload generation tools"""
        self.clear_screen()
        self.print_banner()
        
        payload_dir = self.tools_dir / "payloads"
        if payload_dir.exists():
            payload_files = list(payload_dir.glob("*.txt"))
            print(f"{self.colors['primary']}Available Payload Files{self.colors['reset']}\n")
            
            for i, payload_file in enumerate(payload_files, 1):
                size = payload_file.stat().st_size
                print(f"{self.colors['warning']}[{i}]{self.colors['reset']} {payload_file.name} ({size} bytes)")
        else:
            self.print_status_bar("Payloads directory not found", "WARNING")
        
        self.pause()

    def documentation_menu(self):
        """Documentation menu"""
        self.clear_screen()
        self.print_banner()
        
        docs = [
            ("README.md", "Main documentation"),
            ("docs/TOOLS.md", "Tools documentation"),
            ("install/", "Installation guides"),
            ("scripts/recon/", "Reconnaissance scripts")
        ]
        
        print(f"{self.colors['primary']}Documentation{self.colors['reset']}\n")
        
        for doc, description in docs:
            doc_path = self.project_root.parent.parent / doc
            if doc_path.exists():
                print(f"{self.colors['success']}✓ {doc}: {description}{self.colors['reset']}")
            else:
                print(f"{self.colors['warning']}✗ {doc}: {description} (not found){self.colors['reset']}")
        
        self.pause()

    def config_menu(self):
        """Configuration menu"""
        self.clear_screen()
        self.print_banner()
        
        print(f"{self.colors['primary']}Configuration{self.colors['reset']}\n")
        
        # Show current configuration
        config = {
            "Project Root": str(self.project_root),
            "Virtual Environment": str(self.venv_dir),
            "Reports Directory": str(self.reports_dir),
            "Tools Directory": str(self.tools_dir),
            "Python Version": sys.version.split()[0]
        }
        
        for key, value in config.items():
            print(f"{self.colors['info']}{key}:{self.colors['reset']} {value}")
        
        self.pause()

    def setup_menu(self):
        """Setup menu"""
        while True:
            self.clear_screen()
            self.print_banner()
            self.print_menu("Setup & Installation", self.setup_options)
            
            choice = self.get_user_input("Choose an option: ")
            
            if choice == "0":
                break
            elif choice == "1":
                self.setup_python_env()
            elif choice == "2":
                self.install_dependencies()
            elif choice == "3":
                self.install_security_tools()
            elif choice == "4":
                self.run_tests()
            elif choice == "5":
                self.check_system_status()
            else:
                self.print_status_bar("Invalid option", "ERROR")
                self.pause()

    def exit_program(self):
        """Exit the program"""
        self.clear_screen()
        self.print_banner()
        self.print_status_bar("Thank you for using Bug Hunting Arsenal!", "SUCCESS")
        self.print_status_bar("Stay safe and keep hunting! 🛡️", "INFO")
        sys.exit(0)

    def run(self):
        """Main menu loop"""
        signal.signal(signal.SIGINT, lambda sig, frame: self.exit_program())
        
        while True:
            self.clear_screen()
            self.print_banner()
            self.print_menu("Main Menu", self.main_menu_options)
            
            choice = self.get_user_input("Choose an option: ")
            
            # Find and execute the selected option
            for key, description, func in self.main_menu_options:
                if choice == key:
                    if func:
                        func()
                    break
            else:
                self.print_status_bar("Invalid option", "ERROR")
                self.pause()

def main():
    """Main entry point"""
    try:
        menu = BugHuntingMenu()
        menu.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()