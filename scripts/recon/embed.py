import os
import sys
import time
import json
import hashlib
import mimetypes
import subprocess
import importlib.util
import signal
import shutil
from pathlib import Path
from colorama import Fore, Style, init
from prompt_toolkit import prompt
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.completion import PathCompleter, WordCompleter

init(autoreset=True)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def is_package_installed(package):
    return importlib.util.find_spec(package) is not None

def install_package(package):
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
        print(f"{Fore.GREEN}[+] {package} installed successfully.")
    except subprocess.CalledProcessError:
        print(f"{Fore.RED}[!] Failed to install {package}.")

def check_and_install_packages(packages):
    for package in packages:
        if is_package_installed(package):
            print(f"{Fore.GREEN}[+] {package} is already installed.")
        else:
            print(f"{Fore.YELLOW}[!] {package} is missing. Installing...")
            install_package(package)

def load_config():
    return ["colorama", "prompt_toolkit"]

def handle_interrupt(signal, frame):
    print(f"\n{Fore.RED}[!] Program interrupted. Exiting...")
    sys.exit(0)

def create_ScriptoSVG_file(filename, payload):
    svg_content = f'''<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg" width="200" height="100">
  <script type="text/javascript">
    {payload}
  </script>
  <text x="6" y="50" font-family="Arial" font-size="16" fill="black">Created by: Anom5x</text>
</svg>
'''
    try:
        with open(filename, "w") as file:
            file.write(svg_content)
        print(f"{Fore.GREEN}[+] Created the SVG file: {filename}")
    except IOError as e:
        print(f"{Fore.RED}[!] Error creating SVG file: {e}")

def create_ScriptoPDF_pdf(filename, payload):
    pdf_content = f'''%PDF-1.7
%âãÏÓ
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 3 0 R/Metadata 4 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[5 0 R]/Count 1>>
endobj
3 0 obj
<</JS({payload}\n)/S/JavaScript/Type/Action>>
endobj
4 0 obj
<</Type/Metadata/Subtype/XML/Length 0>>
stream
endstream
endobj
5 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 6 0 R/Resources<</ProcSet[/PDF /Text]>> >>
endobj
6 0 obj
<</Length 44>>
stream
/Courier 12 Tf
100 700 Td
(Created by Anom5x) Tj
ET
endstream
endobj
xref
0 7
0000000000 65535 f
0000000015 00000 n
0000000074 00000 n
0000000128 00000 n
0000000185 00000 n
0000000231 00000 n
0000000318 00000 n
trailer
<</Size 7/Root 1 0 R>>
startxref
382
%%EOF
'''
    try:
        with open(filename, "wb") as file:
            file.write(pdf_content.encode('latin1'))
        print(f"{Fore.GREEN}[+] Created the PDF file: {filename}")
    except IOError as e:
        print(f"{Fore.RED}[!] Error creating PDF file: {e}")

def create_ScriptoHTML_file(filename: str, payload: str) -> None:
    html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Created by Anom5x</title>
  <style>
    body {{ font-family: Arial, Helvetica, sans-serif; margin: 2rem; }}
  </style>
  <script>
  {payload}
  </script>
  </head>
<body>
  <h1>Created by: Anom5x</h1>
  <p>Payload embedded in script block.</p>
</body>
</html>
'''
    try:
        with open(filename, "w", encoding="utf-8") as file:
            file.write(html_content)
        print(f"{Fore.GREEN}[+] Created the HTML file: {filename}")
    except IOError as e:
        print(f"{Fore.RED}[!] Error creating HTML file: {e}")

def print_banner() -> None:
    title = "Scripto Tool Suite"
    subtitle = "by Anom5x"
    bar = f"{Fore.MAGENTA}{'=' * (len(title) + 12)}{Style.RESET_ALL}"
    print(bar)
    print(f"{Fore.CYAN}*** {title} ***{Style.RESET_ALL}")
    print(f"{Fore.BLUE}{subtitle}{Style.RESET_ALL}")
    print(bar)

def pause(message: str = f"{Fore.YELLOW}Press Enter to return to menu...") -> None:
    try:
        prompt(HTML("<ansiyellow>\n[↩]</ansiyellow> " + message))
    except KeyboardInterrupt:
        pass

def prompt_filepath(message: str) -> str:
    completer = PathCompleter(expanduser=True)
    return prompt(HTML(f"<ansicyan>[?]</ansicyan> {message}"), completer=completer).strip().strip('"')

def is_exiftool_available() -> bool:
    return shutil.which('exiftool') is not None

def advise_install_exiftool() -> None:
    print(f"{Fore.YELLOW}[!] exiftool not found in PATH.")
    print("- On Debian/Ubuntu: sudo apt-get update && sudo apt-get install -y exiftool")
    print("- On macOS (Homebrew): brew install exiftool")
    print("- On Windows: download from 'https://exiftool.org/' and add to PATH")

def run_exiftool(args: list[str]) -> tuple[int, str, str]:
    try:
        process = subprocess.run(["exiftool", *args], capture_output=True, text=True)
        return process.returncode, process.stdout, process.stderr
    except FileNotFoundError:
        return 127, "", "exiftool not found"

def exif_view_metadata() -> None:
    if not is_exiftool_available():
        advise_install_exiftool()
        return
    file_path = prompt_filepath("Enter file to inspect: ")
    if not file_path:
        print(f"{Fore.RED}[!] No file provided.")
        return
    if not os.path.isfile(file_path):
        print(f"{Fore.RED}[!] File not found: {file_path}")
        return
    code, out, err = run_exiftool(["-json", "-a", "-u", "-g1", file_path])
    if code != 0:
        print(f"{Fore.RED}[!] exiftool error: {err.strip()}")
        return
    try:
        data = json.loads(out)
        pretty = json.dumps(data, indent=2, ensure_ascii=False)
        print(pretty)
    except json.JSONDecodeError:
        print(out)

def exif_write_tag() -> None:
    if not is_exiftool_available():
        advise_install_exiftool()
        return
    file_path = prompt_filepath("Enter file to modify: ")
    if not os.path.isfile(file_path):
        print(f"{Fore.RED}[!] File not found: {file_path}")
        return
    tag = prompt(HTML("<ansicyan>[?]</ansicyan> Enter tag (e.g., <ansigreen>Comment</ansigreen>): ")).strip()
    value = prompt(HTML("<ansicyan>[?]</ansicyan> Enter value: ")).strip()
    if not tag:
        print(f"{Fore.RED}[!] Tag cannot be empty.")
        return
    code, out, err = run_exiftool([f"-{tag}={value}", "-overwrite_original", file_path])
    if code == 0:
        print(f"{Fore.GREEN}[+] Updated {tag} on {file_path}")
        print(out.strip())
    else:
        print(f"{Fore.RED}[!] exiftool error: {err.strip()}")

def exif_strip_metadata() -> None:
    if not is_exiftool_available():
        advise_install_exiftool()
        return
    file_path = prompt_filepath("Enter file to strip metadata from: ")
    if not os.path.isfile(file_path):
        print(f"{Fore.RED}[!] File not found: {file_path}")
        return
    code, out, err = run_exiftool(["-overwrite_original", "-all=", file_path])
    if code == 0:
        print(f"{Fore.GREEN}[+] Stripped all metadata from {file_path}")
        print(out.strip())
    else:
        print(f"{Fore.RED}[!] exiftool error: {err.strip()}")

def exif_batch_strip() -> None:
    if not is_exiftool_available():
        advise_install_exiftool()
        return
    dir_path = prompt_filepath("Enter directory to process recursively: ")
    if not os.path.isdir(dir_path):
        print(f"{Fore.RED}[!] Directory not found: {dir_path}")
        return
    extensions = prompt(HTML("<ansicyan>[?]</ansicyan> File extensions to target (comma-separated, e.g., jpg,png,mp4). Leave blank for all: ")).strip()
    args = ["-r", "-overwrite_original", "-all=", dir_path]
    if extensions:
        for ext in [e.strip().lstrip('.').lower() for e in extensions.split(',') if e.strip()]:
            args[0:0] = ["-ext", ext]
    code, out, err = run_exiftool(args)
    if code == 0:
        print(f"{Fore.GREEN}[+] Batch strip completed")
        print(out.strip())
    else:
        print(f"{Fore.RED}[!] exiftool error: {err.strip()}")

def file_info() -> None:
    file_path = prompt_filepath("Enter file to analyze: ")
    if not os.path.isfile(file_path):
        print(f"{Fore.RED}[!] File not found: {file_path}")
        return
    size_bytes = os.path.getsize(file_path)
    mime_type, _ = mimetypes.guess_type(file_path)
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            md5_hash.update(chunk)
            sha256_hash.update(chunk)
    print(f"{Fore.CYAN}Path{Style.RESET_ALL}: {file_path}")
    print(f"{Fore.CYAN}Size{Style.RESET_ALL}: {size_bytes} bytes")
    print(f"{Fore.CYAN}MIME{Style.RESET_ALL}: {mime_type or 'unknown'}")
    print(f"{Fore.CYAN}MD5 {Style.RESET_ALL}: {md5_hash.hexdigest()}")
    print(f"{Fore.CYAN}SHA256{Style.RESET_ALL}: {sha256_hash.hexdigest()}")

def base64_encode_file() -> None:
    import base64
    file_path = prompt_filepath("File to Base64-encode: ")
    if not os.path.isfile(file_path):
        print(f"{Fore.RED}[!] File not found: {file_path}")
        return
    default_out = str(Path(file_path).with_suffix(Path(file_path).suffix + ".b64.txt"))
    out_path = prompt(HTML(f"<ansicyan>[?]</ansicyan> Output file (Enter for default: <ansigreen>{default_out}</ansigreen>): ")).strip() or default_out
    with open(file_path, 'rb') as fin, open(out_path, 'wb') as fout:
        base64.encode(fin, fout)
    print(f"{Fore.GREEN}[+] Wrote Base64 to {out_path}")

def base64_decode_file() -> None:
    import base64
    file_path = prompt_filepath("Base64 text file to decode: ")
    if not os.path.isfile(file_path):
        print(f"{Fore.RED}[!] File not found: {file_path}")
        return
    default_out = str(Path(file_path).with_suffix(""))
    out_path = prompt(HTML(f"<ansicyan>[?]</ansicyan> Output binary file (Enter for default: <ansigreen>{default_out}</ansigreen>): ")).strip() or default_out
    with open(file_path, 'rb') as fin, open(out_path, 'wb') as fout:
        base64.decode(fin, fout)
    print(f"{Fore.GREEN}[+] Decoded to {out_path}")

def show_menu():
    clear_screen()
    print_banner()
    print(f"{Fore.YELLOW}[1]{Style.RESET_ALL} ScriptoSVG: Create SVG with embedded JavaScript")
    print(f"{Fore.YELLOW}[2]{Style.RESET_ALL} ScriptoPDF: Create PDF with embedded JavaScript")
    print(f"{Fore.YELLOW}[3]{Style.RESET_ALL} ScriptoHTML: Create HTML with embedded JavaScript")
    print(f"{Fore.YELLOW}[4]{Style.RESET_ALL} ExifTool: View/Write/Strip metadata")
    print(f"{Fore.YELLOW}[5]{Style.RESET_ALL} Utilities: File info, Base64 encode/decode")
    print(f"{Fore.YELLOW}[0]{Style.RESET_ALL} Exit")

def show_exif_menu() -> str:
    print(f"\n{Fore.CYAN}ExifTool Operations{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[1]{Style.RESET_ALL} View metadata (JSON)")
    print(f"{Fore.YELLOW}[2]{Style.RESET_ALL} Write a tag (key=value)")
    print(f"{Fore.YELLOW}[3]{Style.RESET_ALL} Strip all metadata (single file)")
    print(f"{Fore.YELLOW}[4]{Style.RESET_ALL} Batch strip metadata (directory)")
    print(f"{Fore.YELLOW}[0]{Style.RESET_ALL} Back")
    return prompt(HTML("<ansicyan>\n[?]</ansicyan> Choose an option: ")).strip()

def show_utils_menu() -> str:
    print(f"\n{Fore.CYAN}Utilities{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[1]{Style.RESET_ALL} File info (MIME, hashes)")
    print(f"{Fore.YELLOW}[2]{Style.RESET_ALL} Base64 encode file")
    print(f"{Fore.YELLOW}[3]{Style.RESET_ALL} Base64 decode file")
    print(f"{Fore.YELLOW}[0]{Style.RESET_ALL} Back")
    return prompt(HTML("<ansicyan>\n[?]</ansicyan> Choose an option: ")).strip()

def main():
    signal.signal(signal.SIGINT, handle_interrupt)
    
    clear_screen()
    print(f"{Fore.YELLOW}[i] Checking for required packages...\n")
    
    required_packages = load_config()
    check_and_install_packages(required_packages)

    time.sleep(1)
    
    while True:
        show_menu()
        option = prompt(HTML("<ansicyan>\n[?]</ansicyan> Choose an option: ")).strip()

        if option == "1":
            filename = prompt(HTML(f"<ansicyan>[?]</ansicyan> Enter the name for the SVG file (Enter for default: <ansigreen>ScriptoSVG.svg</ansigreen>): ")).strip() or "ScriptoSVG.svg"
            payload = prompt(HTML(f"<ansicyan>[?]</ansicyan> Enter the payload to embed in the SVG (Enter for default: <ansigreen>alert('Anom5x');</ansigreen>): ")).strip() or "alert('AnonKryptiQuz');"
            create_ScriptoSVG_file(filename, payload)
            pause()

        elif option == "2":
            filename = prompt(HTML(f"<ansicyan>[?]</ansicyan> Enter the name for the PDF file (Enter for default: <ansigreen>ScriptoPDF.pdf</ansigreen>): ")).strip() or "ScriptoPDF.pdf"
            payload = prompt(HTML(f"<ansicyan>[?]</ansicyan> Enter the payload to embed in the PDF (Enter for default: <ansigreen>app.alert('Anom5x');</ansigreen>): ")).strip() or "app.alert('AnonKryptiQuz');"
            create_ScriptoPDF_pdf(filename, payload)
            pause()

        elif option == "3":
            filename = prompt(HTML(f"<ansicyan>[?]</ansicyan> Enter the name for the HTML file (Enter for default: <ansigreen>ScriptoHTML.html</ansigreen>): ")).strip() or "ScriptoHTML.html"
            payload = prompt(HTML(f"<ansicyan>[?]</ansicyan> Enter the payload to embed in the HTML (Enter for default: <ansigreen>alert('Anom5x');</ansigreen>): ")).strip() or "alert('AnonKryptiQuz');"
            create_ScriptoHTML_file(filename, payload)
            pause()

        elif option == "4":
            while True:
                sub = show_exif_menu()
                if sub == "1":
                    exif_view_metadata()
                    pause()
                elif sub == "2":
                    exif_write_tag()
                    pause()
                elif sub == "3":
                    exif_strip_metadata()
                    pause()
                elif sub == "4":
                    exif_batch_strip()
                    pause()
                elif sub == "0":
                    break
                else:
                    print(f"{Fore.RED}[!] Invalid option.")
                    pause()

        elif option == "5":
            while True:
                sub = show_utils_menu()
                if sub == "1":
                    file_info()
                    pause()
                elif sub == "2":
                    base64_encode_file()
                    pause()
                elif sub == "3":
                    base64_decode_file()
                    pause()
                elif sub == "0":
                    break
                else:
                    print(f"{Fore.RED}[!] Invalid option.")
                    pause()

        elif option == "0":
            print(f"{Fore.GREEN}[+] Exiting the program. Goodbye!")
            break

        else:
            print(f"{Fore.RED}[!] Wrong option selected. Press Enter to try again.")
            prompt()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"{Fore.RED}\n[!] Operation interrupted. Exiting...")