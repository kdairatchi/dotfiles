Cheat sheet of test commands for the Enhanced Banner Maker script:

### Basic Banner Generation
```bash
# Simple banner with default settings
python3 banner_maker.py --text "Hello World"

# Custom font and color
python3 banner_maker.py --text "Hello World" --font slant --color cyan

# Box-style border
python3 banner_maker.py --text "Hello World" --box --width 60

# With timestamp and author
python3 banner_maker.py --text "My Script" --timestamp --author "John Doe"
```

### List and Preview Options
```bash
# List all available fonts
python3 banner_maker.py --list-fonts

# List first 10 fonts
python3 banner_maker.py --list-fonts | head

# Preview specific font
python3 banner_maker.py --text "Preview" --font block --color yellow
```

### Output and Export Options
```bash
# Save banner to file
python3 banner_maker.py --text "Saved Banner" --out my_banner.txt

# Generate commented banner (Bash style)
python3 banner_maker.py --text "Bash Script" --comment-lang bash --box

# Generate commented banner (Python style)
python3 banner_maker.py --text "Python Script" --comment-lang python --border star
```

### Script Injection
```bash
# Inject into bash script (after shebang)
python3 banner_maker.py --text "My Tool" --insert script.sh --comment-lang bash

# Inject into Python script (top of file)
python3 banner_maker.py --text "My Module" --insert module.py --position top --comment-lang python

# Inject without backup
python3 banner_maker.py --text "Quick Add" --insert quick.sh --no-backup
```

### Runtime Functions
```bash
# Export Bash print function
python3 banner_maker.py --text "Tool Banner" --export-runtime bash > banner_func.sh

# Export Python print function
python3 banner_maker.py --text "Tool Banner" --export-runtime python > banner_func.py

# Use exported function (Bash example)
source banner_func.sh
print_banner

# Use exported function (Python example)
from banner_func import print_banner
print_banner()
```

### Combination Examples
```bash
# Fancy banner with all options
python3 banner_maker.py --text "SUPER TOOL" --font block --color magenta \
  --border double --width 70 --timestamp --author "Team Rocket" --out super_banner.txt

# Quick inject with box style
python3 banner_maker.py --text "System Tool" --font digital --box \
  --insert /usr/local/bin/tool --comment-lang bash --position after-shebang

# Generate runtime function with custom name
python3 banner_maker.py --text "API Service" --font lean --export-runtime python \
  --out api_banner.py --function-name show_api_banner
```

### Interactive Mode
```bash
# Launch interactive mode
python3 banner_maker.py

# Steps in interactive mode:
# 1. Enter banner text
# 2. Choose font
# 3. Select color
# 4. Pick border style
# 5. Set width
# 6. Add timestamp/author if desired
# 7. Choose output option:
#    - Save to file
#    - Inject into script
#    - Generate runtime function
#    - Just display
```

### Verification Commands
```bash
# Check if banner was injected
grep "BANNER_MAKER_BLOCK" your_script.sh

# Verify backup was created
ls -la your_script.sh*

# Test runtime function
python3 -c "from banner_func import print_banner; print_banner()"

# Test bash runtime function
bash -c "source banner_func.sh; print_banner"
```
