#!/usr/bin/env python3
import sys
import pyfiglet
from termcolor import colored
import os
import argparse
from datetime import datetime
import shutil
import textwrap
import time

class EnhancedBannerMaker:
    def __init__(self):
        self.available_fonts = pyfiglet.FigletFont.getFonts()
        self.border_styles = {
            'single': '-', 'double': '=', 'star': '*', 'hash': '#',
            'tilde': '~', 'pipe': '|', 'plus': '+', 'dash': '-',
            'arrow': '>', 'diamond': '<>', 'none': '', 'box': 'box'
        }
        self.color_options = [
            'grey', 'red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white'
        ]
        self.comment_styles = {
            'bash': ('# ', ''), 'python': ('# ', ''), 'c': ('// ', ''),
            'html': ('<!-- ', ' -->'), 'none': ('', '')
        }
        self.insert_positions = {
            'top': 0, 'after-shebang': 1, 'before-end': -1
        }
        self.verbose = False

    def _log(self, message, level='info'):
        if self.verbose:
            color = 'yellow' if level == 'info' else 'red'
            print(colored(f'[{level.upper()}] {message}', color))

    def show_intro(self):
        intro = pyfiglet.figlet_format('Banner Maker Pro', font='big')
        print(colored(intro, 'cyan'))
        print(colored('A comprehensive tool for creating and deploying script banners.\n', 'yellow'))

    def list_fonts(self):
        return sorted(self.available_fonts)

    def generate_banner(self, text, font='standard', color='green', border='single', width=80,
                      timestamp=False, author=None, box=False, align='center'):
        self._log(f'Generating banner with font: {font}, color: {color}, border: {border}')
        try:
            ascii_art = pyfiglet.figlet_format(text, font=font, width=width, justify=align)
        except pyfiglet.FontNotFound:
            self._log(f'Font \'{font}\' not found, falling back to \'standard\'.', 'warn')
            ascii_art = pyfiglet.figlet_format(text, font='standard', width=width, justify=align)

        if border == 'box' or box:
            return self._generate_box_banner(ascii_art, text, color, width, timestamp, author)

        border_char = self.border_styles.get(border, '-')
        border_line = border_char * width if border_char else ''
        colored_art = colored(ascii_art, color)
        banner_lines = []
        if border_char:
            banner_lines.append(border_line)
        banner_lines.extend(colored_art.split('\n'))

        metadata = []
        if timestamp:
            metadata.append(f'Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}')
        if author:
            metadata.append(f'Author: {author}')

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
        self._log('Generating box-style banner.')
        top_bottom = f'+{'-' * (width - 2)}+'
        side = '|'
        colored_art = colored(ascii_art, color)
        art_lines = colored_art.split('\n')
        banner_lines = [top_bottom]
        for line in art_lines:
            padded_line = line.ljust(width - 4) if len(line) < width - 4 else line[:width - 4]
            banner_lines.append(f'{side} {padded_line} {side}')

        if timestamp or author:
            banner_lines.append(f'{side}{'-' * (width - 2)}{side}')
            if timestamp:
                ts = f'Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}'
                banner_lines.append(f'{side} {ts.ljust(width - 4)} {side}')
            if author:
                auth_line = f'Author: {author}'
                banner_lines.append(f'{side} {auth_line.ljust(width - 4)} {side}')
        banner_lines.append(top_bottom)
        return '\n'.join(banner_lines)

    def generate_commented_banner(self, banner_text, comment_style='bash', width=80):
        self._log(f'Generating commented banner for \'{comment_style}\'.')
        comment_start, comment_end = self.comment_styles.get(comment_style, ('# ', ''))
        commented_lines = []
        for line in banner_text.split('\n'):
            if line.strip():
                commented_line = f'{comment_start}{line}{comment_end}'
            else:
                commented_line = f'{comment_start}{comment_end}'
            commented_lines.append(commented_line)
        commented_lines.insert(0, f'{comment_start}=== BANNER_MAKER_BLOCK START ==={comment_end}')
        commented_lines.append(f'{comment_start}=== BANNER_MAKER_BLOCK END ==={comment_end}')
        return '\n'.join(commented_lines)

    def inject_into_script(self, banner_code, target_script, position='after-shebang', backup=True):
        self._log(f'Injecting banner into \'{target_script}\' at position \'{position}\'.')
        try:
            if backup:
                backup_file = f'{target_script}.bak'
                self._log(f'Creating backup: {backup_file}')
                shutil.copy2(target_script, backup_file)
            with open(target_script, 'r') as f:
                content = f.readlines()
            for line in content:
                if 'BANNER_MAKER_BLOCK START' in line:
                    print(colored('Banner already exists. Skipping insertion.', 'yellow'))
                    return False
            insert_pos = 0
            if position == 'after-shebang':
                for i, line in enumerate(content):
                    if line.startswith('#!'):
                        insert_pos = i + 1
                        break
            elif position == 'before-end':
                insert_pos = len(content)
            content.insert(insert_pos, banner_code + '\n\n')
            with open(target_script, 'w') as f:
                f.writelines(content)
            return True
        except Exception as e:
            print(colored(f'Error injecting banner: {e}', 'red'))
            return False

    def process_bulk(self, input_file, output_dir, **kwargs):
        self._log(f'Starting bulk processing from \'{input_file}\'.')
        if not os.path.exists(output_dir):
            self._log(f'Output directory \'{output_dir}\' not found. Creating it.')
            os.makedirs(output_dir)
        with open(input_file, 'r') as f:
            titles = [line.strip() for line in f if line.strip()]
        
        total = len(titles)
        for i, title in enumerate(titles):
            print(colored(f'Processing [{i+1}/{total}]: {title}', 'cyan'))
            banner = self.generate_banner(text=title, **kwargs)
            filename = f'{title.replace(' ', '_').lower()}.txt'
            filepath = os.path.join(output_dir, filename)
            with open(filepath, 'w') as out_f:
                out_f.write(banner)
            self._log(f'Saved banner to \'{filepath}\'')
            time.sleep(0.1) 
        print(colored(f'\nBulk processing complete. Banners saved in \'{output_dir}\'.', 'green'))

    def interactive_menu(self):
        self.show_intro()
        
        opts = {
            'text': 'Hello World', 'font': 'standard', 'color': 'green',
            'border': 'single', 'width': 80, 'timestamp': False,
            'author': None, 'align': 'center'
        }

        def print_menu():
            os.system('clear' if os.name == 'posix' else 'cls')
            print(colored('Banner Preview:', 'yellow'))
            preview = self.generate_banner(**opts)
            print(preview)
            print('\n' + '='*opts['width'])
            print(colored('Interactive Menu - Customize your banner', 'cyan'))
            print('='*opts['width'])
            print(f'1. Text:      {opts['text']}')
            print(f'2. Font:      {opts['font']}')
            print(f'3. Color:     {opts['color']}')
            print(f'4. Border:    {opts['border']}')
            print(f'5. Width:     {opts['width']}')
            print(f'6. Alignment: {opts['align']}')
            print(f'7. Toggle Timestamp: {"On" if opts['timestamp'] else "Off"}')
            print(f"8. Set Author:       {opts['author'] or 'Not set'}")
            print(colored('S: Save/Export | L: List Fonts | Q: Quit', 'yellow'))

        while True:
            print_menu()
            choice = input(colored('Choose an option to edit: ', 'green')).lower()

            if choice == '1':
                opts['text'] = input('Enter new text: ')
            elif choice == '2':
                opts['font'] = input(f'Enter font name (current: {opts['font']}): ')
            elif choice == '3':
                print('Colors:', ', '.join(self.color_options))
                opts['color'] = input(f'Enter color (current: {opts['color']}): ')
            elif choice == '4':
                print('Borders:', ', '.join(self.border_styles.keys()))
                opts['border'] = input(f'Enter border style (current: {opts['border']}): ')
            elif choice == '5':
                try:
                    opts['width'] = int(input(f'Enter width (current: {opts['width']}): '))
                except ValueError:
                    print(colored('Invalid width. Please enter a number.', 'red'))
                    time.sleep(1)
            elif choice == '6':
                align_choice = input('Alignment (left, center, right): ')
                if align_choice in ['left', 'center', 'right']:
                    opts['align'] = align_choice
            elif choice == '7':
                opts['timestamp'] = not opts['timestamp']
            elif choice == '8':
                opts['author'] = input('Enter author name (or leave blank to clear): ') or None
            elif choice == 'l':
                print('\n'.join(self.list_fonts()))
                input('\nPress Enter to continue...')
            elif choice == 's':
                self.export_menu(opts)
                break
            elif choice == 'q':
                break

    def export_menu(self, opts):
        final_banner = self.generate_banner(**opts)
        print(colored('\nFinal Banner:', 'yellow'))
        print(final_banner)
        
        action = input(colored('\nChoose action:\n1. Save to file\n2. Inject into script\n3. Exit\nChoice: ', 'green'))
        if action == '1':
            filename = input('Output filename: ')
            with open(filename, 'w') as f:
                f.write(final_banner)
            print(colored(f'Banner saved to {filename}', 'green'))
        elif action == '2':
            target = input('Target script path: ')
            if not os.path.exists(target):
                print(colored('Script not found.', 'red'))
                return
            lang = input(f'Comment style ({'/'.join(self.comment_styles.keys())}): ')
            pos = input(f'Insert position ({'/'.join(self.insert_positions.keys())}): ')
            commented = self.generate_commented_banner(final_banner, lang, opts['width'])
            if self.inject_into_script(commented, target, pos):
                print(colored(f'Successfully injected banner into {target}', 'green'))

    def run(self):
        parser = argparse.ArgumentParser(
            description='Enhanced Banner Maker',
            formatter_class=argparse.RawTextHelpFormatter
        )
        parser.add_argument('--text', help='Text for the banner')
        parser.add_argument('--font', default='standard', help='Font style')
        parser.add_argument('--color', default='green', help='Text color')
        parser.add_argument('--border', default='single', help='Border style')
        parser.add_argument('--width', type=int, default=80, help='Banner width')
        parser.add_argument('--align', default='center', choices=['left', 'center', 'right'], help='Text alignment')
        parser.add_argument('--timestamp', action='store_true', help='Include timestamp')
        parser.add_argument('--author', help='Include author name')
        parser.add_argument('--out', help='Output file for the banner')
        parser.add_argument('--comment-lang', choices=self.comment_styles.keys(), help='Comment banner for a language')
        parser.add_argument('--insert', help='Script file to inject banner into')
        parser.add_argument('--position', choices=self.insert_positions.keys(), default='after-shebang', help='Injection position')
        parser.add_argument('--no-backup', action='store_true', help='Disable backup during injection')
        parser.add_argument('--list-fonts', action='store_true', help='List all available fonts')
        parser.add_argument('--bulk', help='File with a list of titles for bulk generation')
        parser.add_argument('--bulk-out', default='banners', help='Output directory for bulk generation')
        parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
        
        args = parser.parse_args()
        self.verbose = args.verbose

        if args.list_fonts:
            print('\n'.join(self.list_fonts()))
            sys.exit(0)

        if args.bulk:
            banner_opts = {
                'font': args.font, 'color': args.color, 'border': args.border,
                'width': args.width, 'timestamp': args.timestamp, 'author': args.author,
                'align': args.align
            }
            self.process_bulk(args.bulk, args.bulk_out, **banner_opts)
            return

        if not args.text:
            self.interactive_menu()
            return

        banner = self.generate_banner(
            text=args.text, font=args.font, color=args.color, border=args.border,
            width=args.width, timestamp=args.timestamp, author=args.author, align=args.align
        )
        
        if args.comment_lang:
            banner = self.generate_commented_banner(banner, args.comment_lang, args.width)
        
        if args.insert:
            if self.inject_into_script(banner, args.insert, args.position, not args.no_backup):
                print(colored(f'Successfully injected banner into {args.insert}', 'green'))
            return
        
        print(banner)
        if args.out:
            with open(args.out, 'w') as f:
                f.write(banner)
            print(colored(f'Banner saved to {args.out}', 'green'))

if __name__ == '__main__':
    try:
        maker = EnhancedBannerMaker()
        maker.run()
    except KeyboardInterrupt:
        print(colored('\nOperation cancelled by user.', 'red'))
        sys.exit(0)
    except Exception as e:
        print(colored(f'\nAn unexpected error occurred: {e}', 'red'))
        sys.exit(1)
