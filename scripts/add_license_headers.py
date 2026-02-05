#!/usr/bin/env python3
"""
Script to add GPL-3.0 license headers to all source files.
Copyright (c) 2026 BaoZ. Licensed under GPL-3.0.
"""

import os
from pathlib import Path

# GPL-3.0 header templates
PYTHON_HEADER = '''"""
Phishing Detector - AI-Powered Threat Intelligence System
Copyright (c) 2026 BaoZ

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
"""

'''

JS_HEADER = '''/**
 * Phishing Detector - AI-Powered Threat Intelligence System
 * Copyright (c) 2026 BaoZ
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

'''

def has_license_header(content):
    """Check if file already has a license header."""
    return 'GNU General Public License' in content or 'Copyright (c) 2026 BaoZ' in content

def add_header_to_python(filepath):
    """Add GPL header to Python file."""
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    if has_license_header(content):
        print(f"  ✓ Already has header: {filepath}")
        return False
    
    # Handle shebang
    if content.startswith('#!'):
        lines = content.split('\n', 1)
        new_content = lines[0] + '\n' + PYTHON_HEADER + (lines[1] if len(lines) > 1 else '')
    else:
        new_content = PYTHON_HEADER + content
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(new_content)
    
    print(f"  ✓ Added header: {filepath}")
    return True

def add_header_to_js(filepath):
    """Add GPL header to JS/JSX file."""
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    if has_license_header(content):
        print(f"  ✓ Already has header: {filepath}")
        return False
    
    new_content = JS_HEADER + content
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(new_content)
    
    print(f"  ✓ Added header: {filepath}")
    return True

def main():
    project_root = Path(__file__).parent.parent
    added_count = 0
    
    print("🔍 Adding GPL-3.0 license headers...\n")
    
    # Python files
    print("📝 Processing Python files:")
    py_files = [
        *project_root.glob('app/**/*.py'),
        *project_root.glob('scripts/**/*.py'),
        project_root / 'main.py',
        project_root / 'train_pro.py',
    ]
    
    for filepath in py_files:
        if filepath.exists() and filepath.is_file():
            if add_header_to_python(filepath):
                added_count += 1
    
    # JavaScript/JSX files
    print("\n📝 Processing JavaScript/JSX files:")
    js_files = [
        *project_root.glob('frontend/src/**/*.js'),
        *project_root.glob('frontend/src/**/*.jsx'),
    ]
    
    for filepath in js_files:
        if filepath.exists() and filepath.is_file():
            if add_header_to_js(filepath):
                added_count += 1
    
    print(f"\n✅ Done! Added headers to {added_count} files.")

if __name__ == '__main__':
    main()
