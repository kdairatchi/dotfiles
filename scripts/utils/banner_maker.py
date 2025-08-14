#!/usr/bin/env python3
import sys
import pyfiglet
from termcolor import colored
import os
import argparse
from datetime import datetime
import shutil
import textwrap

class EnhancedBannerMaker:
    def __init__(self):
        self.available_fonts = pyfiglet.FigletFont.getFonts()
        self.border_styles = {
            'single': '-',
            'double': '=',
            'star': '*',
            'hash': '#',
            'tilde': '~',
            'pipe': '|',
            'plus': '+',
            'dash': '-',
            'none': '',
            'box': 'box'
        }
        self.color_options = [
            'grey', 'red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white'
        ]
        self.comment_styles = {
            'bash': ('# ', ''),
            'python': ('# ', ''),
            'c': ('// ', ''),
            'html': ('<!-- ', ' -->'),
            'none': ('', '')
        }
        self.insert_positions = {
            'top': 0,
            'after-shebang': 1,
            'before-end': -1
        }

    def show_intro(self):
        intro = pyfiglet.figlet_format("Banner Maker Pro", font="big")
        print(colored(intro, 'cyan'))
        print(colored("Create and deploy custom banners for your scripts!\n", 'yellow'))

    def list_fonts(self):
        return sorted(self.available_fonts)

    def generate_banner(self, text, font='standard', color='green', border='single', width=80, 
                      timestamp=False, author=None, box=False):
        # Generate ASCII art
        try:
            ascii_art = pyfiglet.figlet_format(text, font=font)
        except pyfiglet.FontNotFound:
            ascii_art = pyfiglet.figlet_format(text, font='standard')

        # Handle box border
        if border == 'box' or box:
            return self._generate_box_banner(ascii_art, text, color, width, timestamp, author)

        # Calculate border
        border_char = self.border_styles.get(border, '-')
        border_line = border_char * width if border_char else ""

        # Color the text
        colored_art = colored(ascii_art, color)

        # Build the banner
        banner_lines = []
        if border_char:
            banner_lines.append(border_line)

        banner_lines.extend(colored_art.split('\n'))

        # Add metadata if requested
        metadata = []
        if timestamp:
            metadata.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        if author:
            metadata.append(f"Author: {author}")

        if metadata:
            if border_char:
                banner_lines.append(border_char * width)
            for line in metadata:
                banner_lines.append(line.center(width))
            if border_char:
                banner_lines.append(border_line)
        elif border_char:
            banner_lines.append(border_line)

        return '\n'.join(banner_lines)

    def _generate_box_banner(self, ascii_art, text, color, width, timestamp, author):
        # Create a box-style banner
        top_bottom = f"+{'-' * (width - 2)}+"
        side = '|'
        
        colored_art = colored(ascii_art, color)
        art_lines = colored_art.split('\n')
        
        banner_lines = [top_bottom]
        
        for line in art_lines:
            if line.strip():
                banner_lines.append(f"{side} {line.ljust(width - 4)} {side}")
            else:
                banner_lines.append(f"{side}{' ' * (width - 2)}{side}")

        # Add metadata if requested
        if timestamp or author:
            banner_lines.append(f"{side}{'-' * (width - 2)}{side}")
            
            if timestamp:
                ts = f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                banner_lines.append(f"{side} {ts.ljust(width - 4)} {side}")
            
            if author:
                auth_line = f"Author: {author}"
                banner_lines.append(f"{side} {auth_line.ljust(width - 4)} {side}")
        
        banner_lines.append(top_bottom)
        return '\n'.join(banner_lines)

    def generate_commented_banner(self, banner_text, comment_style='bash', width=80):
        comment_start, comment_end = self.comment_styles.get(comment_style, ('# ', ''))
        
        commented_lines = []
        for line in banner_text.split('\n'):
            if line.strip():
                commented_line = f"{comment_start}{line.ljust(width - len(comment_start) - len(comment_end))}{comment_end}"
            else:
                commented_line = comment_start + comment_end
            commented_lines.append(commented_line)
        
        # Add marker comments
        commented_lines.insert(0, f"{comment_start}=== BANNER_MAKER_BLOCK START ==={comment_end}")
        commented_lines.append(f"{comment_start}=== BANNER_MAKER_BLOCK END ==={comment_end}")
        
        return '\n'.join(commented_lines)

    def generate_runtime_function(self, banner_text, language='bash', function_name='print_banner'):
        if language == 'bash':
            code = f"""#!/bin/bash
{function_name}() {{
    cat << 'BANNER_EOF'
{banner_text}
BANNER_EOF
}}
"""
        elif language == 'python':
            code = f"""def {function_name}():
    print(r\"\"\"
{banner_text}
\"\"\")
"""
        return code

    def inject_into_script(self, banner_code, target_script, position='after-shebang', backup=True):
        try:
            # Create backup if requested
            if backup:
                shutil.copy2(target_script, f"{target_script}.bak")
            
            with open(target_script, 'r') as f:
                content = f.readlines()
            
            # Check if banner already exists
            for line in content:
                if "BANNER_MAKER_BLOCK START" in line:
                    print(colored("Banner already exists in script. Skipping insertion.", 'yellow'))
                    return False
            
            # Determine insert position
            insert_pos = 0
            if position == 'after-shebang':
                for i, line in enumerate(content):
                    if line.startswith('#!'):
                        insert_pos = i + 1
                        break
            elif position == 'before-end':
                insert_pos = len(content)
            
            # Insert the banner
            content.insert(insert_pos, banner_code + '\n\n')
            
            with open(target_script, 'w') as f:
                f.writelines(content)
            
            return True
        
        except Exception as e:
            print(colored(f"Error injecting banner: {e}", 'red'))
            return False

    def run(self):
        parser = argparse.ArgumentParser(
            description='Enhanced Banner Maker - Create and deploy custom banners for scripts',
            formatter_class=argparse.RawTextHelpFormatter
        )
        
        # Banner content options
        parser.add_argument('--text', help='Text to display in banner')
        parser.add_argument('--font', help='Font style for banner text')
        parser.add_argument('--color', help='Text color')
        parser.add_argument('--border', help='Border style (single, double, star, hash, box, etc.)')
        parser.add_argument('--box', action='store_true', help='Use box-style border')
        parser.add_argument('--width', type=int, default=80, help='Banner width in characters')
        parser.add_argument('--timestamp', action='store_true', help='Include timestamp in banner')
        parser.add_argument('--author', help='Include author name in banner')
        
        # Output options
        parser.add_argument('--out', help='Output file for banner')
        parser.add_argument('--comment-lang', choices=self.comment_styles.keys(), 
                           help='Generate commented banner for specific language')
        
        # Script injection options
        parser.add_argument('--insert', help='Script file to inject banner into')
        parser.add_argument('--position', choices=self.insert_positions.keys(), default='after-shebang',
                           help='Where to insert banner in target script')
        parser.add_argument('--no-backup', action='store_true', help='Disable backup when injecting')
        
        # Runtime options
        parser.add_argument('--export-runtime', choices=['bash', 'python'],
                           help='Export a runtime function to print the banner')
        
        # Info options
        parser.add_argument('--list-fonts', action='store_true', help='List available fonts')
        
        args = parser.parse_args()
        
        if args.list_fonts:
            for font in self.list_fonts():
                print(font)
            sys.exit(0)
        
        # Interactive mode if no arguments
        if not any(vars(args).values()):
            self.interactive_mode()
            return
        
        # Generate banner
        banner = self.generate_banner(
            text=args.text or "My Script",
            font=args.font or 'standard',
            color=args.color or 'green',
            border=args.border or ('box' if args.box else 'single'),
            width=args.width,
            timestamp=args.timestamp,
            author=args.author
        )
        
        # Handle different output options
        if args.export_runtime:
            runtime_code = self.generate_runtime_function(banner, args.export_runtime)
            print(runtime_code)
            if args.out:
                with open(args.out, 'w') as f:
                    f.write(runtime_code)
            return
        
        if args.comment_lang:
            banner = self.generate_commented_banner(banner, args.comment_lang, args.width)
        
        if args.insert:
            success = self.inject_into_script(
                banner,
                args.insert,
                args.position,
                not args.no_backup
            )
            if success:
                print(colored(f"Successfully injected banner into {args.insert}", 'green'))
            return
        
        # Default output
        print(banner)
        if args.out:
            with open(args.out, 'w') as f:
                f.write(banner)
            print(colored(f"Banner saved to {args.out}", 'green'))

    def interactive_mode(self):
        self.show_intro()
        
        # Get banner text
        text = input(colored("Enter banner text: ", 'green'))
        
        # Font selection
        print(colored("\nAvailable fonts (sample):", 'yellow'))
        sample_fonts = ['standard', 'slant', 'block', 'script', 'bubble']
        for i, font in enumerate(sample_fonts, 1):
            print(f"{i}. {font} - {pyfiglet.figlet_format('Hi', font=font).splitlines()[0]}")
        print("6. Show all fonts (long list)")
        
        font_choice = input(colored("\nChoose font (1-6 or name): ", 'green'))
        if font_choice.isdigit() and int(font_choice) == 6:
            print("\n".join(self.list_fonts()))
            font = input(colored("\nEnter font name: ", 'green'))
        elif font_choice.isdigit() and 1 <= int(font_choice) <= 5:
            font = sample_fonts[int(font_choice)-1]
        else:
            font = font_choice
        
        # Color selection
        print(colored("\nAvailable colors:", 'yellow'))
        for i, color in enumerate(self.color_options, 1):
            print(colored(f"{i}. {color}", color))
        color_choice = input(colored("\nChoose color (1-8 or name): ", 'green'))
        color = self.color_options[int(color_choice)-1] if color_choice.isdigit() else color_choice
        
        # Border selection
        print(colored("\nBorder styles:", 'yellow'))
        for i, (name, char) in enumerate(self.border_styles.items(), 1):
            if name == 'box':
                sample = "+-----+"
            elif char:
                sample = char * 5
            else:
                sample = "none"
            print(f"{i}. {name} ({sample})")
        
        border_choice = input(colored("\nChoose border (1-9 or name): ", 'green'))
        if border_choice.isdigit():
            border = list(self.border_styles.keys())[int(border_choice)-1]
        else:
            border = border_choice
        
        # Additional options
        width = int(input(colored("\nBanner width (default 80): ", 'green') or "80"))
        timestamp = input(colored("Include timestamp? (y/n): ", 'green')).lower() == 'y'
        author = None
        if input(colored("Include author? (y/n): ", 'green')).lower() == 'y':
            author = input(colored("Author name: ", 'green'))
        
        # Generate banner
        banner = self.generate_banner(
            text=text,
            font=font,
            color=color,
            border=border,
            width=width,
            timestamp=timestamp,
            author=author
        )
        
        print(colored("\nGenerated Banner:\n", 'yellow'))
        print(banner)
        
        # Output options
        action = input(colored("\nChoose action:\n1. Save to file\n2. Inject into script\n3. Generate runtime function\n4. Just show\nChoice (1-4): ", 'green'))
        
        if action == '1':
            filename = input(colored("Output filename: ", 'green'))
            with open(filename, 'w') as f:
                f.write(banner)
            print(colored(f"Banner saved to {filename}", 'green'))
        
        elif action == '2':
            target = input(colored("Target script path: ", 'green'))
            lang = input(colored("Comment style (bash/python/c/html/none): ", 'green'))
            position = input(colored("Insert position (top/after-shebang/before-end): ", 'green'))
            
            commented_banner = self.generate_commented_banner(banner, lang, width)
            success = self.inject_into_script(
                commented_banner,
                target,
                position,
                True
            )
            if success:
                print(colored(f"Successfully injected banner into {target}", 'green'))
        
        elif action == '3':
            lang = input(colored("Language (bash/python): ", 'green'))
            func = input(colored("Function name (default print_banner): ", 'green') or "print_banner")
            
            runtime_code = self.generate_runtime_function(banner, lang, func)
            print(colored("\nRuntime function:\n", 'yellow'))
            print(runtime_code)
            
            if input(colored("Save to file? (y/n): ", 'green')).lower() == 'y':
                filename = input(colored("Filename: ", 'green'))
                with open(filename, 'w') as f:
                    f.write(runtime_code)
                print(colored(f"Saved to {filename}", 'green'))

if __name__ == "__main__":
    try:
        maker = EnhancedBannerMaker()
        maker.run()
    except KeyboardInterrupt:
        print(colored("\nOperation cancelled by user.", 'red'))
        sys.exit(0)
    except Exception as e:
        print(colored(f"\nError: {e}", 'red'))
        sys.exit(1)