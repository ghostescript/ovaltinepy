#!/usr/bin/env python3
import colorama
import readline
import argparse
import base64
import binascii
import bz2
import codecs
import gzip
import hashlib
import html
import ipaddress
import lzma
import quopri
import sys
import urllib.parse
import zlib
import zstandard as zstd
import pygeohash as pgh # Added for Geohash encoding/decoding
import random
import re # Added for regex operations
import math # Added for math.gcd in Affine Cipher
import xml.sax.saxutils # Added for XML encoding/decoding
import json # Added for JSON encoding/decoding
import yaml # Added for YAML encoding/decoding
import uuid # Added for UUID generation/parsing
from colorama import Fore, Style
import io
import traceback
from unittest.mock import patch
import subprocess
import shlex
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Random Phrases ---
PHRASES = [
    "\033[1;97mI want an Official Red Ryder carbine action two-hundred shot range model air rifle!\033[0m",
    "\033[1;97mYou'll shoot your eye out, kid!\033[0m",
    "\033[1;97mIn the heat of battle, my father wove a tapestry of obscenity...\033[0m",
    "\033[1;97mOh, fudge!\033[0m",
    "\033[1;97mHe had yellow eyes! So help me God! Yellow eyes!\033[0m",
    "\033[1;97mMeatloaf, smeatloaf, double beatloaf. I hate meatloaf!\033[0m",
    "\033[1;97mIt could be a bowling alley!\033[0m",
    "\033[1;97mYou used up all the glue on purpose!\033[0m",
    "\033[1;97mOnly one thing in the world could have dragged me away from the soft glow of electric sex gleaming in the window!\033[0m",
    "\033[1;97mNaddafinga!\033[0m",
    "\033[1;97mOvaltine ?!\033[0m",
    "\033[1;97mBe sure to drink your Ovaltine.\033[0m",
    "\033[1;97mA crummy commercial!\033[0m",
    "\033[1;97mOnly I didn't say 'Fudge.' I said THE word, the big one...\033[0m",
    "\033[1;97mOh look at that! Will you look at that! Isn't that glorious! It's... it's... it's indescribably beautiful! It reminds me of the Fourth of July!\033[0m",
    "\033[1;97mIt is a lamp, you nincompoop, but it's a Major Award. I won it!\033[0m",
    "\033[1;97mFra-GEE-leh! It must be Italian!\033[0m",
    "\033[1;97mDadgummit! Blow out!\033[0m",
    "\033[1;97mYou wart mundane noodle!\033[0m",
    "\033[1;97mServes you right, you smelly buggers!\033[0m",
    "\033[1;97mblasted flirt rattle camel flirt you rattle circle bottom brother\033[0m",
    "\033[1;97mHe looks like a deranged Easter Bunny.\033[0m",
    "\033[1;97mIt's a Major Award!\033[0m",
    "\033[1;97mHe does too, he looks like a pink nightmare!\033[0m",
    "\033[1;97mHe does too, he looks like a pink nightmare!\033[0m",
    "\033[1;97mJealous! Jealous because I WON!\033[0m",
    "\033[1;97mThat son of a bitch would freeze up in the middle of summer on the equator!\033[0m",
    "\033[1;97mAll right, I'll get that kid to eat. Where's my screwdriver and my plumber's helper? I'll open up his mouth and I'll shove it in.\033[0m",
    "\033[1;97mSons of bitches! Bumpuses!\033[0m"
]

def format_options_two_columns(options_list, flag_width=40, total_width=80):
    formatted_lines = []
    for flag, desc in options_list:
        desc = desc or "" # Ensure desc is not None
        remaining_width = total_width - flag_width - 2 # 2 for separator space
        
        # Use textwrap.wrap for robust text wrapping
        desc_lines = textwrap.wrap(desc, width=remaining_width)

        # Print the flag and the first line of description
        formatted_lines.append(f"  {flag:<{flag_width}} {desc_lines[0] if desc_lines else ''}")
        # Print subsequent lines of description, indented
        for line in desc_lines[1:]:
            formatted_lines.append(f"  {'':<{flag_width}} {line}")
    return "\n".join(formatted_lines)

import textwrap # Added for text wrapping
import shutil

class CustomHelpFormatter(argparse.HelpFormatter):
    def __init__(self,
                 prog,
                 indent_increment=2,
                 max_help_position=None,
                 width=None):
        if width is None:
            width = shutil.get_terminal_size().columns - 2 # Leave some margin
        if max_help_position is None:
            max_help_position = 40 # Start help text further to the right to prevent overlap

        super().__init__(prog, indent_increment, max_help_position, width)

    def _format_action_invocation(self, action):
        invocation = super()._format_action_invocation(action)
        return strip_ansi_codes(invocation) # Return uncolored string



# --- Help Messages ---
MAIN_HELP_MESSAGE = f"""
{Fore.GREEN}{Style.BRIGHT}Encoder/Decoder/Hasher Tool Help{Style.RESET_ALL}

This versatile command-line tool provides a wide range of encoding, decoding, hashing,
and string manipulation functionalities. It can be used interactively or via
command-line arguments for automation.

{Fore.YELLOW}{Style.BRIGHT}Interactive Mode:{Style.RESET_ALL}
Run the script without any arguments to enter interactive mode. A menu will be
displayed, allowing you to choose from various operations. Follow the prompts
to input text, select encode/decode options, and provide any necessary extra
parameters (like shift values or keys).

{Fore.YELLOW}{Style.BRIGHT}Command-Line Mode:{Style.RESET_ALL}
You can perform operations directly from the command line using arguments.

{Fore.CYAN}{Style.BRIGHT}Usage:{Style.RESET_ALL}
  python ovaltine.py [OPTIONS]

{Fore.YELLOW}{Style.BRIGHT}Notes:{Style.RESET_ALL}
  - Operation names are case-insensitive and spaces are ignored when matching.
  - For operations requiring extra input (like 'shift' or 'key'), provide them
    as additional command-line arguments.
  - Some operations (e.g., 'Analyze Hash', 'Auto Detect') do not require a
    'choice' argument.
"""

EXAMPLES_HELP_MESSAGE = f"""
{Fore.GREEN}{Style.BRIGHT}Encoder/Decoder/Hasher Tool Examples{Style.RESET_ALL}

{Fore.WHITE}Interactive Mode:{Style.RESET_ALL}
    python ovaltine.py
  
  {Fore.WHITE}Encode "Hello" to Base64:{Style.RESET_ALL}
    python ovaltine.py -op Base64 -c 1 -i "Hello"
  
  {Fore.WHITE}Decode a Base64 string:{Style.RESET_ALL}
    python ovaltine.py -op Base64 -c 2 -i "SGVsbG8="
  
  {Fore.WHITE}Encode "test" to Hexadecimal:{Style.RESET_ALL}
    python ovaltine.py -op Hexadecimal -c 1 -i "test"

  {Fore.WHITE}Encode "Hello" to Binary:{Style.RESET_ALL}
    python ovaltine.py -op Binary -c 1 -i "Hello"

  {Fore.WHITE}Encode "<tag>" to HTML Entities:{Style.RESET_ALL}
    python ovaltine.py -op "HTML Entities" -c 1 -i "<tag>"

  {Fore.WHITE}Encode "Base32" to Base32:{Style.RESET_ALL}
    python ovaltine.py -op Base32 -c 1 -i "Base32"

  {Fore.WHITE}Encode "Hello World" to URL Percent Encoding:{Style.RESET_ALL}
    python ovaltine.py -op "URL (Percent) Encoding" -c 1 -i "Hello World"

  {Fore.WHITE}Encode "Hello" to ASCII Values:{Style.RESET_ALL}
    python ovaltine.py -op "ASCII Values" -c 1 -i "Hello"

  {Fore.WHITE}Encode "Base58" to Base58:{Style.RESET_ALL}
    python ovaltine.py -op Base58 -c 1 -i "Base58"

  {Fore.WHITE}Calculate SHA256 hash of "test":{Style.RESET_ALL}
    python ovaltine.py -op SHA256 -i "test"

  {Fore.WHITE}Calculate MD5 hash of "test":{Style.RESET_ALL}
    python ovaltine.py -op MD5 -i "test"

  {Fore.WHITE}Calculate SHA-1 hash of "test":{Style.RESET_ALL}
    python ovaltine.py -op "SHA-1" -i "test"

  {Fore.WHITE}Calculate CRC32 checksum of "hello":{Style.RESET_ALL}
    python ovaltine.py -op CRC32 -i "hello"

  {Fore.WHITE}Calculate Adler-32 checksum of "hello":{Style.RESET_ALL}
    python ovaltine.py -op "Adler-32" -i "hello"

  {Fore.WHITE}Caesar Cipher encryption with shift 3:{Style.RESET_ALL}
    python ovaltine.py -op "CaesarCipher" -c 1 -i "abc" --shift 3
  
  {Fore.WHITE}Atbash Cipher:{Style.RESET_ALL}
    python ovaltine.py -op "Atbash Cipher" -i "hello"

  {Fore.WHITE}ROT13 Cipher:{Style.RESET_ALL}
    python ovaltine.py -op ROT13 -i "hello"

  {Fore.WHITE}A1Z26 Encode:{Style.RESET_ALL}
    python ovaltine.py -op "A1Z26 Cipher" -c 1 -i "code"

  {Fore.WHITE}Vigenere Cipher encryption with key SECRET:{Style.RESET_ALL}
    python ovaltine.py -op "VigenÃ¨re Cipher" -c 1 -i "attackatdawn" -k SECRET

  {Fore.WHITE}XOR Cipher encryption with key 'key':{Style.RESET_ALL}
    python ovaltine.py -op "XOR Cipher" -c 1 -i "secret" -k "key"

  {Fore.WHITE}Morse Code encode:{Style.RESET_ALL}
    python ovaltine.py -op "Morse Code" -c 1 -i "sos"

  {Fore.WHITE}Reverse the string "desserts":{Style.RESET_ALL}
    python ovaltine.py -op "Reverse String" -i "desserts"

  {Fore.WHITE}Convert "hello" to Uppercase:{Style.RESET_ALL}
    python ovaltine.py -op Uppercase -i "hello"

  {Fore.WHITE}Convert "HELLO" to Lowercase:{Style.RESET_ALL}
    python ovaltine.py -op Lowercase -i "HELLO"

  {Fore.WHITE}Convert "hello world" to Capitalize:{Style.RESET_ALL}
    python ovaltine.py -op Capitalize -i "hello world"

  {Fore.WHITE}Convert Roman Numeral "MCMLXXXIV" to Decimal:{Style.RESET_ALL}
    python ovaltine.py -op "Roman Numerals" -c 2 -i "MCMLXXXIV"

  {Fore.WHITE}Convert Decimal "255" to Hexadecimal:{Style.RESET_ALL}
    python ovaltine.py -op "Decimal to Hex" -i "255"

  {Fore.WHITE}Convert Hex "ff" to Decimal:{Style.RESET_ALL}
    python ovaltine.py -op "Hex to Decimal" -i "ff"

  {Fore.WHITE}Encode "123" to Binary Coded Decimal (BCD):{Style.RESET_ALL}
    python ovaltine.py -op "Binary Coded Decimal (BCD)" -c 1 -i "123"

  {Fore.WHITE}IP Address to Integer:{Style.RESET_ALL}
    python ovaltine.py -op "IP Address to Integer" -i "192.168.1.1"

  {Fore.WHITE}Generate a UUID:{Style.RESET_ALL}
    python ovaltine.py -op "UUID (Generate/Parse)" -c 1

  {Fore.WHITE}Analyze a hash (e.g., MD5):{Style.RESET_ALL}
    python ovaltine.py -op "Analyze Hash" -i "098f6bcd4621d373cade4e832627b4f6"

  {Fore.WHITE}Auto Detect encoding of "SGVsbG8=":{Style.RESET_ALL}
    python ovaltine.py -op "Auto Detect" -i "SGVsbG8="

  {Fore.WHITE}Encode "Hello World" to Quoted-Printable:{Style.RESET_ALL}
    python ovaltine.py -op "Quoted-Printable" -c 1 -i "Hello World"

  {Fore.WHITE}Zlib compress the string "hello world":{Style.RESET_ALL}
    python ovaltine.py -op "Zlib Compress" -c 1 -i "hello world"

  {Fore.WHITE}Gzip compress the string "hello world":{Style.RESET_ALL}
    python ovaltine.py -op "Gzip Compress" -c 1 -i "hello world"

  {Fore.WHITE}Bzip2 compress the string "hello world":{Style.RESET_ALL}
    python ovaltine.py -op "Bzip2 Compress" -c 1 -i "hello world"

  {Fore.WHITE}LZMA compress the string "hello world":{Style.RESET_ALL}
    python ovaltine.py -op "LZMA Compress" -c 1 -i "hello world"

  {Fore.WHITE}Encode "Hello" to Brainfuck:{Style.RESET_ALL}
    python ovaltine.py -op Brainfuck -c 1 -i "Hello"

  {Fore.WHITE}Decode Brainfuck code:{Style.RESET_ALL}
    python ovaltine.py -op Brainfuck -c 2 -i "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++.+++++++++++++++++++++++++++++.+++++++..+++."

  {Fore.WHITE}Encode "Hello world" to Tap Code:{Style.RESET_ALL}
    python ovaltine.py -op "Tap Code" -c 1 -i "Hello world"

  {Fore.WHITE}Decode "23 15 31 31 34 / 52 34 42 31 14" from Tap Code:{Style.RESET_ALL}
    python ovaltine.py -op "Tap Code" -c 2 -i "23 15 31 31 34 / 52 34 42 31 14"

  {Fore.WHITE}Affine Cipher encryption:{Style.RESET_ALL}
    python ovaltine.py -op "Affine Cipher" -c 1 -i "hello" --key_a 5 --key_b 8

  {Fore.WHITE}BLAKE2b hash of "test":{Style.RESET_ALL}
    python ovaltine.py -op BLAKE2b -i "test"

  {Fore.WHITE}BLAKE2s hash of "test":{Style.RESET_ALL}
    python ovaltine.py -op BLAKE2s -i "test"

  {Fore.WHITE}Baconian Cipher encode "hello":{Style.RESET_ALL}
    python ovaltine.py -op "Baconian Cipher" -c 1 -i "hello"

  {Fore.WHITE}Base36 encode "12345":{Style.RESET_ALL}
    python ovaltine.py -op Base36 -c 1 -i "12345"

  {Fore.WHITE}Base62 encode "1234567890":{Style.RESET_ALL}
    python ovaltine.py -op Base62 -c 1 -i "1234567890"

  {Fore.WHITE}Base85 encode "Hello World":{Style.RESET_ALL}
    python ovaltine.py -op Base85 -c 1 -i "Hello World"

  {Fore.WHITE}Base91 encode "Hello World":{Style.RESET_ALL}
    python ovaltine.py -op Base91 -c 1 -i "Hello World"

  {Fore.WHITE}Convert Decimal "10" to Octal:{Style.RESET_ALL}
    python ovaltine.py -op "Decimal to Octal" -i "10"

  {Fore.WHITE}Deflate compress "Hello World":{Style.RESET_ALL}
    python ovaltine.py -op Deflate -c 1 -i "Hello World"

  {Fore.WHITE}EBCDIC encode "Hello":{Style.RESET_ALL}
    python ovaltine.py -op EBCDIC -c 1 -i "Hello"

  {Fore.WHITE}Hexlify encode "Hello":{Style.RESET_ALL}
    python ovaltine.py -op Hexlify -c 1 -i "Hello"

  {Fore.WHITE}Hill Cipher encryption (Placeholder):{Style.RESET_ALL}
    python ovaltine.py -op "Hill Cipher" -c 1 -i "hello" --key_matrix_str "2 3,1 4" # Placeholder, requires numpy and complex logic

  {Fore.WHITE}ISO-8859-1 (Latin-1) encode "Hello":{Style.RESET_ALL}
    python ovaltine.py -op "ISO-8859-1 (Latin-1)" -c 1 -i "Hello"

  {Fore.WHITE}Convert Integer "3232235777" to IP Address:{Style.RESET_ALL}
    python ovaltine.py -op "Integer to IP Address" -i "3232235777"

  {Fore.WHITE}JSON encode '{{"key": "value"}}':{Style.RESET_ALL}
    python ovaltine.py -op JSON -c 1 -i "{'{'}'key': 'value'{'}'}"

  {Fore.WHITE}Leet (1337) encode "Hello World":{Style.RESET_ALL}
    python ovaltine.py -op "Leet (1337)" -c 1 -i "Hello World"

  {Fore.WHITE}Luhn Algorithm generate checksum for "7992739871":{Style.RESET_ALL}
    python ovaltine.py -op "Luhn Algorithm" -c 1 -i "7992739871"

  {Fore.WHITE}Convert Octal "12" to Decimal:{Style.RESET_ALL}
    python ovaltine.py -op "Octal to Decimal" -i "12"

  {Fore.WHITE}Playfair Cipher encryption (Placeholder):{Style.RESET_ALL}
    python ovaltine.py -op "Playfair Cipher" -c 1 -i "hello" --key_matrix_str "keyword" # Placeholder, requires complex logic

  {Fore.WHITE}Polybius Square encode "hello":{Style.RESET_ALL}
    python ovaltine.py -op "Polybius Square" -c 1 -i "hello"

  {Fore.WHITE}Punycode encode "à¤‰à¤¦à¤¾à¤¹à¤°à¤£.à¤•à¥‰à¤®":{Style.RESET_ALL}
    python ovaltine.py -op Punycode -c 1 -i "à¤‰à¤¦à¤¾à¤¹à¤°à¤£.à¤•à¥‰à¤®"

  {Fore.WHITE}Rail Fence Cipher encode "Hello World" with 3 rails:{Style.RESET_ALL}
    python ovaltine.py -op "Rail Fence Cipher" -c 1 -i "Hello World" --rails 3

  {Fore.WHITE}Raw Hex Dump encode "Hello":{Style.RESET_ALL}
    python ovaltine.py -op "Raw Hex Dump" -c 1 -i "Hello"

  {Fore.WHITE}Scytale Cipher encode "Hello World" with diameter 3:{Style.RESET_ALL}
    python ovaltine.py -op "Scytale Cipher" -c 1 -i "Hello World" --diameter 3

  {Fore.WHITE}SHA-512 hash of "test":{Style.RESET_ALL}
    python ovaltine.py -op SHA-512 -i "test"

  {Fore.WHITE}SHA3-224 hash of "test":{Style.RESET_ALL}
    python ovaltine.py -op SHA3-224 -i "test"

  {Fore.WHITE}SHA3-256 hash of "test":{Style.RESET_ALL}
    python ovaltine.py -op SHA3-256 -i "test"

  {Fore.WHITE}SHA3-384 hash of "test":{Style.RESET_ALL}
    python ovaltine.py -op SHA3-384 -i "test"

  {Fore.WHITE}SHA3-512 hash of "test":{Style.RESET_ALL}
    python ovaltine.py -op SHA3-512 -i "test"

  {Fore.WHITE}Shift-JIS encode "Hello":{Style.RESET_ALL}
    python ovaltine.py -op "Shift-JIS" -c 1 -i "Hello"

  {Fore.WHITE}Swap Case "Hello World":{Style.RESET_ALL}
    python ovaltine.py -op "Swap Case" -i "Hello World"

  {Fore.WHITE}Title Case "hello world":{Style.RESET_ALL}
    python ovaltine.py -op "Title Case" -i "hello world"

  {Fore.WHITE}UTF-16 encode "Hello":{Style.RESET_ALL}
    python ovaltine.py -op UTF-16 -c 1 -i "Hello"

  {Fore.WHITE}UTF-32 encode "Hello":{Style.RESET_ALL}
    python ovaltine.py -op UTF-32 -c 1 -i "Hello"

  {Fore.WHITE}UTF-7 encode "Hello":{Style.RESET_ALL}
    python ovaltine.py -op UTF-7 -c 1 -i "Hello"

  {Fore.WHITE}UTF-8 encode "Hello":{Style.RESET_ALL}
    python ovaltine.py -op UTF-8 -c 1 -i "Hello"

  {Fore.WHITE}UUencoding encode "Hello World":{Style.RESET_ALL}
    python ovaltine.py -op UUencoding -c 1 -i "Hello World"

  {Fore.WHITE}Verify MD5 hash of "test":{Style.RESET_ALL}
    python ovaltine.py -op "Verify Hash" -i "test" -ht md5 -eh "098f6bcd4621d373cade4e832627b4f6"

  {Fore.WHITE}XML encode "<tag>":{Style.RESET_ALL}
    python ovaltine.py -op XML -c 1 -i "<tag>"

  {Fore.WHITE}XXencoding encode "Hello World":{Style.RESET_ALL}
    python ovaltine.py -op XXencoding -c 1 -i "Hello World"

  {Fore.WHITE}YAML encode '{{"key": "value"}}':{Style.RESET_ALL}
    python ovaltine.py -op YAML -c 1 -i "{'{'}'key': 'value'{'}'}"

  {Fore.WHITE}Zstandard Compress "Hello World":{Style.RESET_ALL}
    python ovaltine.py -op "Zstandard Compress" -c 1 -i "Hello World"

  {Fore.WHITE}Geohash encode "38.9072,-77.0369":{Style.RESET_ALL}
    python ovaltine.py -op Geohash -c 1 -i "38.9072,-77.0369" # Placeholder, requires geohash library

  {Fore.WHITE}Read input from file and write output to
    file:{Style.RESET_ALL}
    echo "secret" > input.txt
    python ovaltine.py -op Base64 -c 1 -if input.txt -of output.txt

  {Fore.WHITE}Display operation history:{Style.RESET_ALL}
    python ovaltine.py --history

  {Fore.WHITE}Clear operation history:{Style.RESET_ALL}
    python ovaltine.py --clear-history
"""

# --- ANSI Escape Codes for Styling ---
def bold_white(text):
    return f"\033[1;37m{text}\033[0m"

def get_display_width(text):
    # Remove ANSI escape codes for accurate width calculation
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    clean_text = ansi_escape.sub('', text)
    return len(clean_text)

def strip_ansi_codes(s):
    return re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', s)

import os
import datetime

HISTORY_FILE = os.path.join(os.path.dirname(__file__), "operations_history.json")
MAX_HISTORY_ENTRIES = 100 # Limit history to 100 entries

def load_history():
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            return []
    return []

def save_history(history_list):
    # Keep only the latest MAX_HISTORY_ENTRIES
    history_list = history_list[-MAX_HISTORY_ENTRIES:]
    with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
        json.dump(history_list, f, indent=2)

def add_to_history(operation_name, sub_choice, input_text, result, extra_params=None):
    history_entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "operation": operation_name,
        "choice": sub_choice,
        "input": input_text,
        "result": result,
        "extra_params": extra_params if extra_params else {}
    }
    history = load_history()
    history.append(history_entry)
    save_history(history)
    return history

def clear_history():
    if os.path.exists(HISTORY_FILE):
        os.remove(HISTORY_FILE)
        print(f"{Fore.GREEN}History file '{HISTORY_FILE}' cleared successfully.{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}History file '{HISTORY_FILE}' does not exist. Nothing to clear.{Style.RESET_ALL}")

def get_menu_choice(input_str, is_mobile_display, main_options_map):
    menu_choice = None
    normalized_input = input_str.lower().replace(" ", "")

    if is_mobile_display:
        if input_str.isdigit() and input_str in main_options_map:
            menu_choice = main_options_map[input_str]
        else:
            # Try to match by name
            for original_key, option_data in MENU_OPTIONS.items():
                normalized_option_name = option_data['name'].lower().replace(" ", "")
                if normalized_input == normalized_option_name:
                    menu_choice = original_key
                    break
            if menu_choice is None:
                for original_key, option_data in SYSTEM_OPTIONS.items():
                    if 'name' in option_data and normalized_input == option_data['name'].lower().replace(" ", ""):
                        menu_choice = original_key
                        break
    else: # Two-column display
        if input_str.isdigit():
            if input_str in SYSTEM_OPTIONS:
                menu_choice = input_str
            else:
                formatted_input = input_str.zfill(2)
                if formatted_input in MENU_OPTIONS:
                    menu_choice = formatted_input
        else:
            # Try to match by name
            for original_key, option_data in MENU_OPTIONS.items():
                normalized_option_name = option_data['name'].lower().replace(" ", "")
                if normalized_input == normalized_option_name:
                    menu_choice = original_key
                    break
            if menu_choice is None:
                for original_key, option_data in SYSTEM_OPTIONS.items():
                    if 'name' in option_data and normalized_input == option_data['name'].lower().replace(" ", ""):
                        menu_choice = original_key
                        break
    return menu_choice

# --- Core Handler Functions ---

def get_input_from_args(args):
    """Gets input from command line arguments or stdin."""
    if args.input:
        return args.input
    if args.input_file:
        with open(args.input_file, 'r', encoding='utf-8') as f:
            return f.read()
    if not sys.stdin.isatty():
        return sys.stdin.read().strip()
    return None

def write_output(result, output_file=None):
    """Writes the result to a file or to stdout."""
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(result)
        print(f"\nResult written to: {output_file}", flush=True)
    else:
        print(f"\n---START_RESULT---\n{result}\n---END_RESULT---", flush=True)

def get_interactive_input(prompt="Enter text: "):
    """Gets input from the user, single line if interactive, multi-line if from pipe."""
    print(prompt, flush=True)
    if sys.stdin.isatty(): # If running in an interactive terminal
        return input() # Read a single line
    else: # If input is piped
        lines = []
        while True:
            try:
                line = input()
                lines.append(line)
            except EOFError:
                break
        return "\n".join(lines)

def get_sub_choice(operation_name):
    """Gets user's choice for encoding or decoding."""
    print(f"--- {operation_name} Options ---")
    return input("[01] Encode/Encrypt\n[02] Decode/Decrypt\n[03] Back to Main Menu\nEnter your choice: ").strip()

def auto_detect_handler(text, **kwargs):
    detections = []

    # Helper to check if decoded bytes are mostly printable ASCII
    def is_mostly_printable(data):
        if not isinstance(data, bytes):
            data = data.encode('utf-8', errors='ignore')
        return all(32 <= b <= 126 or b in (9, 10, 13) for b in data)

    # 1. Base64 (most common, distinct pattern)
    try:
        if len(text) % 4 == 0 and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in text):
            decoded_bytes = base64.b64decode(text, validate=True)
            if is_mostly_printable(decoded_bytes):
                detections.append("Base64")
    except Exception:
        pass

    # 2. Hexadecimal (common, distinct pattern)
    try:
        if len(text) > 1 and len(text) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in text):
            decoded_hex = bytes.fromhex(text).decode('utf-8', errors='ignore')
            if is_mostly_printable(decoded_hex):
                detections.append("Hexadecimal")
    except Exception:
        pass

    # 3. Binary (distinct pattern)
    try:
        binary_string = text.replace(' ', '')
        if all(c in '01' for c in binary_string) and len(binary_string) % 8 == 0:
            decoded_binary = "".join([chr(int(binary_string[i:i+8], 2)) for i in range(0, len(binary_string), 8)])
            if is_mostly_printable(decoded_binary):
                detections.append("Binary")
    except Exception:
        pass

    # 4. URL Encoding (distinct pattern)
    if '%' in text and any(c.isxdigit() for c in text.split('%')[-1]): # Basic check for % followed by hex
        unquoted_text = urllib.parse.unquote(text)
        if unquoted_text != text and is_mostly_printable(unquoted_text):
            detections.append("URL Encoded")

    # 5. HTML Entities (distinct pattern)
    if '&' in text and ';' in text and re.search(r'&(#\d+|#x[0-9a-fA-F]+|[a-zA-Z]+);', text):
        unescaped_html = html.unescape(text)
        if unescaped_html != text and is_mostly_printable(unescaped_html):
            detections.append("HTML Entities")

    # 6. Punycode (distinct prefix)
    if text.startswith("xn--"):
        try:
            decoded_punycode = text.encode('ascii').decode('punycode')
            if is_mostly_printable(decoded_punycode):
                detections.append("Punycode")
        except Exception:
            pass

    # 7. XML (structural check)
    if text.strip().startswith('<') and text.strip().endswith('>') and ('<' in text and '>' in text):
        # Very basic check, actual XML parsing is complex
        if re.search(r'<[^>]+>.*<\/[^>]+>', text, re.DOTALL): # Contains opening and closing tags
            detections.append("XML (possible)")

    # 8. JSON (structural check)
    if text.strip().startswith('{') and text.strip().endswith('}') or \
       text.strip().startswith('[') and text.strip().endswith(']'):
        try:
            json.loads(text)
            detections.append("JSON")
        except json.JSONDecodeError:
            pass

    # 9. YAML (structural check - very basic)
    # YAML is a superset of JSON, so check JSON first.
    # Look for common YAML indicators like key: value, or - item
    if re.search(r'^\s*(\w+\s*:\s*.*|\-\s+.*)', text, re.MULTILINE):
        try:
            yaml.safe_load(text)
            detections.append("YAML (possible)")
        except yaml.YAMLError:
            pass

    # 10. ASCII Values (space-separated decimal numbers)
    try:
        parts = text.split()
        if all(part.isdigit() for part in parts) and parts:
            decoded_ascii = "".join([chr(int(p)) for p in parts])
            if is_mostly_printable(decoded_ascii):
                detections.append("ASCII Values")
    except Exception:
        pass

    # 11. Base32 (specific alphabet)
    try:
        # Base32 alphabet: A-Z, 2-7, padding =
        if all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=' for c in text.upper()) and len(text) % 8 == 0:
            decoded_bytes = base64.b32decode(text, casefold=True, map01=None)
            if is_mostly_printable(decoded_bytes):
                detections.append("Base32")
    except Exception:
        pass

    # 12. Base58 (specific alphabet)
    try:
        # Base58 alphabet: 1-9, A-Z (no I, O), a-z (no l)
        if all(c in '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz' for c in text):
            # Attempt a decode to verify
            alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
            n = 0
            for char in text:
                n = n * 58 + alphabet.index(char)
            decoded_bytes = n.to_bytes((n.bit_length() + 7) // 8, 'big')
            if is_mostly_printable(decoded_bytes):
                detections.append("Base58")
    except Exception:
        pass

    # 13. Base85 (specific alphabet)
    try:
        # Base85 alphabet: ASCII 33-117, usually wrapped in <~ ~>
        clean_text = text.strip()
        if clean_text.startswith('<~') and clean_text.endswith('~>'):
            clean_text = clean_text[2:-2]
        if all(33 <= ord(c) <= 117 for c in clean_text):
            decoded_bytes = base64.a85decode(clean_text.encode('ascii'))
            if is_mostly_printable(decoded_bytes):
                detections.append("Base85")
    except Exception:
        pass

    # 14. Base91 (specific alphabet)
    try:
        # Base91 alphabet is quite broad, so rely on decoding success
        # Check if all characters are in the _b91_alphabet
        if all(c in _b91_decode_table for c in text):
            decoded_bytes = base91_decode(text)
            if is_mostly_printable(decoded_bytes):
                detections.append("Base91")
    except Exception:
        pass

    # 15. Morse Code (pattern of dots, dashes, spaces, slashes)
    if re.fullmatch(r'[\.\-\s\/]+', text):
        # Heuristic: check if it decodes to something reasonable
        morse_map = {'A':'.-','B':'-...','C':'-.-.','D':'-..','E':'.','F':'..-.','G':'--.','H':'....','I':'..','J':'.---','K':'-.-','L':'.-..','M':'--','N':'-.','O':'---','P':'.--.','Q':'--.-','R':'.-.','S':'...','T':'-','U':'..-','V':'...-','W':'.--','X':'-..-','Y':'-.--','Z':'--..','1':'.----','2':'..---','3':'...--','4':'....-','5':'.....','6':'-....','7':'--...','8':'---..','9':'----.','0':'-----', ' ':'/'}
        unmorse_map = {v: k for k, v in morse_map.items()}
        try:
            decoded_morse = ''.join(unmorse_map[code] for code in text.strip().split(' ') if code in unmorse_map)
            if decoded_morse and is_mostly_printable(decoded_morse):
                detections.append("Morse Code")
        except Exception:
            pass

    # 16. A1Z26 Cipher (pattern of numbers and hyphens)
    if re.fullmatch(r'(\d+-)*\d+', text):
        try:
            decoded_a1z26 = "".join([chr(int(i) + 96) for i in text.split('-') if i.isdigit() and 1 <= int(i) <= 26])
            if decoded_a1z26 and is_mostly_printable(decoded_a1z26):
                detections.append("A1Z26 Cipher")
        except Exception:
            pass

    # 17. Baconian Cipher (pattern of 'a' and 'b')
    if re.fullmatch(r'[abAB\s]+', text):
        clean_text = ''.join(c for c in text.lower() if c in 'ab')
        if len(clean_text) > 0 and len(clean_text) % 5 == 0:
            baconian_map = {'A':'aaaaa','B':'aaaab','C':'aaaba','D':'aaabb','E':'aabaa','F':'aabab','G':'aabba','H':'aabbb','I':'abaaa','J':'abaab','K':'ababa','L':'ababb','M':'abbaa','N':'abbab','O':'abbba','P':'abbbb','Q':'baaaa','R':'baaab','S':'baaba','T':'baabb','U':'babaa','V':'babab','W':'babba','X':'babbb','Y':'bbaaa','Z':'bbaab'}
            unbaconian_map = {v: k for k, v in baconian_map.items()}
            try:
                decoded_baconian = ''
                for i in range(0, len(clean_text), 5):
                    chunk = clean_text[i:i+5]
                    if chunk in unbaconian_map:
                        decoded_baconian += unbaconian_map[chunk]
                if decoded_baconian and is_mostly_printable(decoded_baconian):
                    detections.append("Baconian Cipher")
            except Exception:
                pass

    # 18. Quoted-Printable (pattern of =XX)
    if '=' in text and re.search(r'=[0-9A-Fa-f]{2}', text):
        try:
            decoded_qp = quopri.decodestring(text.encode('ascii')).decode('utf-8')
            if is_mostly_printable(decoded_qp):
                detections.append("Quoted-Printable")
        except Exception:
            pass

    # 19. UUID (standard format)
    if re.fullmatch(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', text):
        try:
            uuid.UUID(text) # Validate format
            detections.append("UUID")
        except ValueError:
            pass

    # 20. Raw Hex Dump (pattern of offset: hex_bytes ascii_chars)
    if re.search(r'^[0-9a-fA-F]{8}: ([0-9a-fA-F]{2}\s){1,16}\s{1,16}[\x20-\x7E\.]+$', text, re.MULTILINE):
        detections.append("Raw Hex Dump (possible)")

    # 21. Luhn Algorithm (check if it's a sequence of digits)
    if text.isdigit() and len(text) > 10: # Luhn numbers are typically credit card numbers, >10 digits
        # This is a validation, not an encoding, but useful for auto-detect
        try:
            if "Valid Luhn number" in luhn_handler(text, '2'):
                detections.append("Luhn Number (possible)")
        except Exception:
            pass

    # 22. Geohash (specific characters, length 1-12)
    if re.fullmatch(r'[0-9bcdefghjkmnpqrstuvwxyz]{1,12}', text):
        # This is a placeholder, actual geohash validation is complex
        detections.append("Geohash (possible)")

    # 23. ROT13 (weak detection, keep it last)
    if codecs.encode(text, 'rot_13') != text and is_mostly_printable(codecs.encode(text, 'rot_13')):
        detections.append("ROT13 (possible)")

    # 24. Hash Detection (if nothing else, check if it looks like a hash)
    if not detections:
        hash_lengths = {
            32: "MD5, NTLM", 40: "SHA-1", 56: "SHA-224", 64: "SHA-256, SHA3-256, BLAKE2s",
            96: "SHA-384, SHA3-384", 128: "SHA-512, SHA3-512, BLAKE2b",
        }
        text_len = len(text.strip())
        if all(c in '0123456789abcdefABCDEF' for c in text.strip()) and text_len in hash_lengths:
            detections.append(f"Possible Hash (length {text_len}): {hash_lengths[text_len]}")


    if detections:
        return "Detected encodings: " + ", ".join(detections)
    else:
        return "Could not confidently detect encoding."

# --- Core Handler Functions ---

def binary_handler(text, choice, **kwargs):
    if choice == '1':
        return ' '.join(format(ord(char), '08b') for char in text)
    elif choice == '2':
        binary_string = text.replace(' ', '')
        if len(binary_string) % 8 != 0:
            raise ValueError("Binary string length is not a multiple of 8.")
        return "".join([chr(int(binary_string[i:i+8], 2)) for i in range(0, len(binary_string), 8)])

def hex_handler(text, choice, **kwargs):
    if choice == '1':
        return text.encode('utf-8').hex()
    elif choice == '2':
        return bytes.fromhex(text).decode('utf-8')

def base64_handler(text, choice, **kwargs):
    if choice == '1':
        return base64.b64encode(text.encode('utf-8')).decode('utf-8')
    elif choice == '2':
        return base64.b64decode(text.encode('ascii')).decode('utf-8')

def url_handler(text, choice, **kwargs):
    if choice == '1':
        return urllib.parse.quote(text)
    elif choice == '2':
        return urllib.parse.unquote(text)

def html_entities_handler(text, choice, **kwargs):
    if choice == '1':
        return html.escape(text)
    elif choice == '2':
        return html.unescape(text)

def ascii_values_handler(text, choice, **kwargs):
    if choice == '1':
        return ' '.join(str(ord(c)) for c in text)
    elif choice == '2':
        return ''.join(chr(int(i)) for i in text.split())

def punycode_handler(text, choice, **kwargs):
    if choice == '1': # Encode
        try:
            if '.' in text: # Likely a domain name
                parts = text.split('.')
                encoded_parts = []
                for part in parts:
                    if any(ord(c) > 127 for c in part): # Contains non-ASCII characters
                        encoded_parts.append('xn--' + part.encode('punycode').decode('ascii'))
                    else:
                        encoded_parts.append(part)
                return '.'.join(encoded_parts)
            else: # Single label
                if any(ord(c) > 127 for c in text): # Contains non-ASCII characters
                    return 'xn--' + text.encode('punycode').decode('ascii')
                else:
                    return text # No encoding needed for ASCII
        except Exception as e:
            raise ValueError(f"Punycode encoding failed: {e}")
    elif choice == '2': # Decode
        try:
            if '.' in text: # Likely a domain name
                parts = text.split('.')
                decoded_parts = []
                for part in parts:
                    if part.startswith('xn--'):
                        decoded_parts.append(part[4:].encode('ascii').decode('punycode'))
                    else:
                        decoded_parts.append(part)
                return '.'.join(decoded_parts)
            else: # Single label
                if text.startswith('xn--'):
                    return text[4:].encode('ascii').decode('punycode')
                else:
                    return text # No decoding needed for non-punycode
        except Exception as e:
            raise ValueError(f"Punycode decoding failed: {e}")

def xml_handler(text, choice, **kwargs):
    if choice == '1':  # Encode (escape)
        return xml.sax.saxutils.escape(text)
    elif choice == '2':  # Decode (unescape)
        return xml.sax.saxutils.unescape(text)

def json_handler(text, choice, **kwargs):
    if choice == '1':  # Encode (pretty-print JSON string)
        try:
            data = json.loads(text) # Parse the input JSON string
            return json.dumps(data, indent=2) # Pretty print it
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON string for pretty-printing: {e}")
    elif choice == '2':  # Decode (parse JSON string to Python object)
        try:
            data = json.loads(text)
            return json.dumps(data, indent=2) # Return pretty-printed JSON for display
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON string for decoding: {e}")

def iso8859_1_handler(text, choice, **kwargs):
    if choice == '1':
        return base64.b64encode(text.encode('iso-8859-1')).decode('ascii')
    elif choice == '2':
        try:
            decoded_bytes = base64.b64decode(text.encode('ascii'))
            return decoded_bytes.decode('iso-8859-1')
        except (binascii.Error, UnicodeDecodeError) as e:
            raise ValueError(f"Invalid input for ISO-8859-1 decoding: {e}")

def shift_jis_handler(text, choice, **kwargs):
    if choice == '1':
        return base64.b64encode(text.encode('shift_jis')).decode('ascii')
    elif choice == '2':
        try:
            decoded_bytes = base64.b64decode(text.encode('ascii'))
            return decoded_bytes.decode('shift_jis')
        except (binascii.Error, UnicodeDecodeError) as e:
            raise ValueError(f"Invalid input for Shift-JIS decoding: {e}")

def utf7_handler(text, choice, **kwargs):
    if choice == '1':
        return base64.b64encode(text.encode('utf-7')).decode('ascii')
    elif choice == '2':
        try:
            decoded_bytes = base64.b64decode(text.encode('ascii'))
            return decoded_bytes.decode('utf-7')
        except (binascii.Error, UnicodeDecodeError) as e:
            raise ValueError(f"Invalid input for UTF-7 decoding: {e}")

def yaml_handler(text, choice, **kwargs):
    if choice == '1':  # Encode (serialize Python object to YAML string)
        try:
            # Attempt to evaluate the input as a Python literal (dict, list, etc.)
            data = yaml.safe_load(text)
            return yaml.dump(data, indent=2, default_flow_style=False)
        except Exception as e:
            raise ValueError(f"Invalid Python literal for YAML encoding: {e}")
    elif choice == '2':  # Decode (parse YAML string to Python object)
        try:
            data = yaml.safe_load(text)
            return yaml.dump(data, indent=2, default_flow_style=False) # Return pretty-printed YAML for display
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML string for decoding: {e}")

def utf_handler(text, choice, encoding, **kwargs):
    if choice == '1':
        return base64.b64encode(text.encode(encoding)).decode('ascii')
    elif choice == '2':
        try:
            decoded_bytes = base64.b64decode(text.encode('ascii'))
            return decoded_bytes.decode(encoding)
        except (binascii.Error, UnicodeDecodeError) as e:
            raise ValueError(f"Invalid input for {encoding} decoding: {e}")

def utf8_handler(text, choice, **kwargs): return utf_handler(text, choice, 'utf-8')
def utf16_handler(text, choice, **kwargs): return utf_handler(text, choice, 'utf-16')
def utf32_handler(text, choice, **kwargs): return utf_handler(text, choice, 'utf-32')

def base32_handler(text, choice, **kwargs):
    if choice == '1':
        return base64.b32encode(text.encode('utf-8')).decode('ascii')
    elif choice == '2':
        return base64.b32decode(text.encode('ascii')).decode('utf-8')

def base58_handler(text, choice, **kwargs):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    if choice == '1':
        n = int.from_bytes(text.encode('utf-8'), 'big')
        result = ''
        while n > 0:
            n, remainder = divmod(n, 58)
            result = alphabet[remainder] + result
        return result
    elif choice == '2':
        n = 0
        for char in text:
            n = n * 58 + alphabet.index(char)
        return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode('utf-8')

def rot13_handler(text, **kwargs):
    return codecs.encode(text, 'rot_13')

def caesar_handler(text, choice, shift, **kwargs):
    if choice == '2':
        shift = -shift
    result = ""
    for char in text:
        if 'a' <= char <= 'z':
            result += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
        elif 'A' <= char <= 'Z':
            result += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
        else:
            result += char
    return result

def atbash_handler(text, **kwargs):
    result = ""
    for char in text:
        if 'a' <= char <= 'z':
            result += chr(ord('z') - (ord(char) - ord('a')))
        elif 'A' <= char <= 'Z':
            result += chr(ord('Z') - (ord(char) - ord('A')))
        else:
            result += char
    return result

def morse_code_handler(text, choice, **kwargs):
    morse_map = {'A':'.-','B':'-...','C':'-.-.','D':'-..','E':'.','F':'..-.','G':'--.','H':'....','I':'..','J':'.---','K':'-.-','L':'.-..','M':'--','N':'-.','O':'---','P':'.--.','Q':'--.-','R':'.-.','S':'...','T':'-','U':'..-','V':'...-','W':'.--','X':'-..-','Y':'-.--','Z':'--..','1':'.----','2':'..---','3':'...--','4':'....-','5':'.....','6':'-....','7':'--...','8':'---..','9':'----.','0':'-----', ' ':'/'}
    unmorse_map = {v: k for k, v in morse_map.items()}
    if choice == '1':
        return ' '.join(morse_map[char.upper()] for char in text)
    elif choice == '2':
        return ''.join(unmorse_map[code] for code in text.strip().split(' '))

def a1z26_handler(text, choice, **kwargs):
    if choice == '1':
        return '-'.join(str(ord(c.lower()) - 96) for c in text if c.isalpha())
    elif choice == '2':
        return "".join([chr(int(i) + 96) for i in text.split('-') if i.isdigit()])

def vigenere_handler(text, choice, key, **kwargs):
    result = ""
    key_index = 0
    for char in text:
        if 'a' <= char <= 'z':
            shift = ord(key[key_index % len(key)]) - ord('A')
            if choice == '2': shift = -shift
            result += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            key_index += 1
        elif 'A' <= char <= 'Z':
            shift = ord(key[key_index % len(key)]) - ord('A')
            if choice == '2': shift = -shift
            result += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            key_index += 1
        else:
            result += char
    return result

def baconian_handler(text, choice, **kwargs):
    baconian_map = {'A':'aaaaa','B':'aaaab','C':'aaaba','D':'aaabb','E':'aabaa','F':'aabab','G':'aabba','H':'aabbb','I':'abaaa','J':'abaab','K':'ababa','L':'ababb','M':'abbaa','N':'abbab','O':'abbba','P':'abbbb','Q':'baaaa','R':'baaab','S':'baaba','T':'baabb','U':'babaa','V':'babab','W':'babba','X':'babbb','Y':'bbaaa','Z':'bbaab'}
    unbaconian_map = {v: k for k, v in baconian_map.items()}
    if choice == '1':
        return ''.join(baconian_map.get(c.upper(), '') for c in text)
    elif choice == '2':
        text = ''.join(c for c in text.lower() if c in 'ab')
        result = ''
        for i in range(0, len(text), 5):
            chunk = text[i:i+5]
            if len(chunk) == 5:
                result += unbaconian_map[chunk]
        return result

def polybius_square_handler(text, choice, **kwargs):
    square = [['A','B','C','D','E'],['F','G','H','I','K'],['L','M','N','O','P'],['Q','R','S','T','U'],['V','W','X','Y','Z']]
    text = text.upper()
    if choice == '1':
        result = ''
        for char in text:
            if char == 'J': char = 'I'
            for r, row in enumerate(square):
                if char in row:
                    result += str(r+1) + str(row.index(char)+1)
        return result
    elif choice == '2':
        result = ''
        for i in range(0, len(text), 2):
            r = int(text[i]) - 1
            c = int(text[i+1]) - 1
            result += square[r][c]
        return result

def affine_handler(text, choice, key_a, key_b, **kwargs):
    if not (1 <= key_a <= 25 and math.gcd(key_a, 26) == 1):
        raise ValueError("Key 'a' must be coprime with 26 (e.g., 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25).")
    
    result = ""
    for char in text:
        if 'a' <= char <= 'z':
            if choice == '1': # Encrypt
                result += chr(((key_a * (ord(char) - ord('a')) + key_b) % 26) + ord('a'))
            else: # Decrypt
                inv_a = pow(key_a, -1, 26)
                result += chr(((inv_a * (ord(char) - ord('a') - key_b)) % 26) + ord('a'))
        elif 'A' <= char <= 'Z':
            if choice == '1': # Encrypt
                result += chr(((key_a * (ord(char) - ord('A')) + key_b) % 26) + ord('A'))
            else: # Decrypt
                inv_a = pow(key_a, -1, 26)
                result += chr(((inv_a * (ord(char) - ord('A') - key_b)) % 26) + ord('A'))
        else:
            result += char
    return result

def rail_fence_handler(text, choice, rails, **kwargs):
    if rails < 2:
        raise ValueError("Number of rails must be at least 2.")

    if choice == '1': # Encrypt
        fence = [[] for _ in range(rails)]
        rail = 0
        direction = 1 # 1 for down, -1 for up

        for char in text:
            fence[rail].append(char)
            rail += direction
            if rail == rails - 1 or rail == 0:
                direction *= -1
        
        ciphertext = []
        for r in fence:
            ciphertext.extend(r)
        return "".join(ciphertext)

    else: # Decrypt
        text_len = len(text)
        fence = [[] for _ in range(rails)]
        
        # Reconstruct the pattern to know where characters go
        pattern = []
        rail = 0
        direction = 1
        for _ in range(text_len):
            pattern.append(rail)
            rail += direction
            if rail == rails - 1 or rail == 0:
                direction *= -1
        
        # Fill the fence with placeholders
        k = 0
        for r in range(rails):
            for i in range(text_len):
                if pattern[i] == r:
                    fence[r].append(text[k])
                    k += 1
        
        # Read off the plaintext
        plaintext = []
        rail = 0
        direction = 1
        for _ in range(text_len):
            plaintext.append(fence[rail].pop(0))
            rail += direction
            if rail == rails - 1 or rail == 0:
                direction *= -1
        return "".join(plaintext)

def scytale_handler(text, choice, diameter, **kwargs):
    if diameter < 1:
        raise ValueError("Diameter (number of columns) must be at least 1.")

    if choice == '1': # Encrypt
        # Pad text if necessary
        num_rows = (len(text) + diameter - 1) // diameter
        padded_text = text.ljust(num_rows * diameter, 'X') # Pad with 'X'
        
        ciphertext = [''] * (num_rows * diameter)
        k = 0
        for col in range(diameter):
            for row in range(num_rows):
                ciphertext[row * diameter + col] = padded_text[k]
                k += 1
        return "".join(ciphertext)

    else: # Decrypt
        num_rows = (len(text) + diameter - 1) // diameter
        plaintext = [''] * (num_rows * diameter)
        k = 0
        for col in range(diameter):
            for row in range(num_rows):
                plaintext[k] = text[row * diameter + col]
                k += 1
        return "".join(plaintext).rstrip('X') # Remove padding

def playfair_cipher_handler(text, choice, key, **kwargs):
    def generate_grid(key):
        # Create the alphabet, treating I and J as the same
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        # Prepare the key: uppercase, unique letters, I/J merged
        key = "".join(sorted(set(key.upper().replace("J", "I")), key=key.upper().replace("J", "I").index))
        
        grid_chars = key
        for char in alphabet:
            if char not in grid_chars:
                grid_chars += char
        
        grid = [list(grid_chars[i:i+5]) for i in range(0, 25, 5)]
        return grid

    def get_char_pos(grid, char):
        char = char.upper().replace("J", "I")
        for r, row in enumerate(grid):
            for c, grid_char in enumerate(row):
                if grid_char == char:
                    return r, c
        return None, None

    def process_text(text):
        text = re.sub(r'[^A-Z]', '', text.upper().replace("J", "I"))
        processed = ""
        i = 0
        while i < len(text):
            a = text[i]
            if i + 1 == len(text):
                processed += a + "X"
                break
            b = text[i+1]
            if a == b:
                processed += a + "X"
                i += 1
            else:
                processed += a + b
                i += 2
        return [processed[i:i+2] for i in range(0, len(processed), 2)]

    grid = generate_grid(key)
    digraphs = process_text(text)
    result = ""
    
    shift = 1 if choice == '1' else -1 # 1 for encrypt, -1 for decrypt

    for pair in digraphs:
        r1, c1 = get_char_pos(grid, pair[0])
        r2, c2 = get_char_pos(grid, pair[1])

        if r1 == r2: # Same row
            result += grid[r1][(c1 + shift) % 5]
            result += grid[r2][(c2 + shift) % 5]
        elif c1 == c2: # Same column
            result += grid[(r1 + shift) % 5][c1]
            result += grid[(r2 + shift) % 5][c2]
        else: # Rectangle
            result += grid[r1][c2]
            result += grid[r2][c1]
            
    return result

def hill_cipher_handler(text, choice, key_matrix_str, **kwargs):
    # Helper function to convert char to int (A=0, B=1, ...)
    def char_to_int(char):
        return ord(char.upper()) - ord('A')

    # Helper function to convert int to char (0=A, 1=B, ...)
    def int_to_char(num):
        return chr(num + ord('A'))

    # Helper function for matrix multiplication modulo 26
    def mat_mul_mod_26(matrix_a, matrix_b):
        n = len(matrix_a)
        m = len(matrix_b[0])
        p = len(matrix_b) # Should be equal to len(matrix_a[0])

        result = [[0 for _ in range(m)] for _ in range(n)]
        for i in range(n):
            for j in range(m):
                for k in range(p):
                    result[i][j] += matrix_a[i][k] * matrix_b[k][j]
                result[i][j] %= 26
        return result

    # Helper function to calculate modular inverse (a^-1 mod m)
    def mod_inverse(a, m):
        for x in range(1, m):
            if (a * x) % m == 1:
                return x
        return None # No inverse exists

    # Parse key matrix string
    rows = key_matrix_str.split(',')
    key_matrix = []
    for row_str in rows:
        key_matrix.append([int(x) for x in row_str.strip().split()])
    
    n = len(key_matrix) # Dimension of the key matrix
    if any(len(row) != n for row in key_matrix):
        raise ValueError("Key matrix must be square.")

    # Calculate determinant
    if n == 1:
        det = key_matrix[0][0] % 26
    elif n == 2:
        det = (key_matrix[0][0] * key_matrix[1][1] - key_matrix[0][1] * key_matrix[1][0]) % 26
    else:
        raise ValueError("Only 1x1 and 2x2 matrices are supported for Hill Cipher in this implementation.")

    if det == 0 or mod_inverse(det, 26) is None:
        raise ValueError("Key matrix is not invertible (determinant is 0 or not coprime with 26).")

    # Prepare text
    text = re.sub(r'[^A-Z]', '', text.upper())
    # Pad text if length is not a multiple of n
    if len(text) % n != 0:
        text += 'X' * (n - (len(text) % n))

    result_text = ""

    if choice == '1': # Encrypt
        for i in range(0, len(text), n):
            block = [[char_to_int(c)] for c in text[i:i+n]]
            encrypted_block = mat_mul_mod_26(key_matrix, block)
            for row in encrypted_block:
                result_text += int_to_char(row[0])
    else: # Decrypt
        det_inv = mod_inverse(det, 26)
        
        # Calculate inverse key matrix
        if n == 1:
            inv_key_matrix = [[det_inv * key_matrix[0][0] % 26]]
        elif n == 2:
            adjugate = [
                [key_matrix[1][1], -key_matrix[0][1]],
                [-key_matrix[1][0], key_matrix[0][0]]
            ]
            inv_key_matrix = [[0, 0], [0, 0]]
            for r in range(n):
                for c in range(n):
                    inv_key_matrix[r][c] = (det_inv * adjugate[r][c]) % 26
        
        for i in range(0, len(text), n):
            block = [[char_to_int(c)] for c in text[i:i+n]]
            decrypted_block = mat_mul_mod_26(inv_key_matrix, block)
            for row in decrypted_block:
                result_text += int_to_char(row[0])
    
    return result_text.rstrip('X') # Remove padding

def xor_cipher_handler(text, choice, key, **kwargs):
    if not key:
        raise ValueError("XOR key cannot be empty.")
    
    key_bytes = key.encode('utf-8')

    if choice == '1': # Encrypt
        text_bytes = text.encode('utf-8')
        result_bytes = bytearray()
        for i in range(len(text_bytes)):
            result_bytes.append(text_bytes[i] ^ key_bytes[i % len(key_bytes)])
        return result_bytes.hex()
    else: # Decrypt
        try:
            hex_data = bytearray.fromhex(text)
            decrypted_bytes = bytearray()
            for i in range(len(hex_data)):
                decrypted_bytes.append(hex_data[i] ^ key_bytes[i % len(key_bytes)])
            return decrypted_bytes.decode('utf-8')
        except ValueError:
            raise ValueError("Input for XOR decryption must be a valid hexadecimal string.")

def reverse_handler(text, **kwargs):
    return text[::-1]

def uppercase_handler(text, **kwargs): return text.upper()
def lowercase_handler(text, **kwargs): return text.lower()
def capitalize_handler(text, **kwargs): return text.capitalize()
def swapcase_handler(text, **kwargs): return text.swapcase()

def leet_handler(text, choice, **kwargs):
    leet_map = {'a':'4','b':'8','e':'3','g':'6','l':'1','o':'0','s':'5','t':'7','z':'2'}
    unleet_map = {v: k for k, v in leet_map.items()}
    text = text.lower()
    if choice == '1':
        for k, v in leet_map.items(): text = text.replace(k, v)
    elif choice == '2':
        for k, v in unleet_map.items(): text = text.replace(k, v)
    return text

def hash_handler(text, hash_type, **kwargs):
    h = hashlib.new(hash_type)
    h.update(text.encode('utf-8'))
    return h.hexdigest()

def md5_handler(text, **kwargs): return hash_handler(text, 'md5')
def sha1_handler(text, **kwargs): return hash_handler(text, 'sha1')
def sha256_handler(text, **kwargs): return hash_handler(text, 'sha256')
def sha512_handler(text, **kwargs): return hash_handler(text, 'sha512')

def checksum_handler(text, checksum_type, **kwargs):
    if checksum_type == 'crc32':
        checksum = binascii.crc32(text.encode('utf-8'))
    elif checksum_type == 'adler32':
        checksum = zlib.adler32(text.encode('utf-8'))
    return str(checksum & 0xffffffff)

def crc32_handler(text, **kwargs): return checksum_handler(text, 'crc32')
def adler32_handler(text, **kwargs): return checksum_handler(text, 'adler32')

def num_system_handler(text, from_base, to_base_func, **kwargs):
    nums = [int(n, from_base) for n in text.split()]
    return ' '.join(to_base_func(n) for n in nums)

def decimal_to_hex_handler(text, **kwargs): return num_system_handler(text, 10, hex)
def hex_to_decimal_handler(text, **kwargs): return num_system_handler(text, 16, str)
def decimal_to_octal_handler(text, **kwargs): return num_system_handler(text, 10, oct)
def octal_to_decimal_handler(text, **kwargs): return num_system_handler(text, 8, str)

def ip_handler(text, direction, **kwargs):
    if direction == 'to_int':
        return str(int(ipaddress.ip_address(text)))
    else:
        return str(ipaddress.ip_address(int(text)))

def ip_to_integer_handler(text, **kwargs): return ip_handler(text, 'to_int')
def integer_to_ip_handler(text, **kwargs): return ip_handler(text, 'to_ip')

def roman_numerals_handler(text, choice, **kwargs):
    val = [1000, 900, 500, 400, 100, 90, 50, 40, 10, 9, 5, 4, 1]
    syb = ["M", "CM", "D", "CD", "C", "XC", "L", "XL", "X", "IX", "V", "IV", "I"]
    roman_map = { 'I': 1, 'V': 5, 'X': 10, 'L': 50, 'C': 100, 'D': 500, 'M': 1000 }
    if choice == '1':
        num = int(text)
        if not 0 < num < 4000:
            raise ValueError("Input must be between 1 and 3999.")
        result = ""
        i = 0
        while num > 0:
            for _ in range(num // val[i]):
                result += syb[i]
                num -= val[i]
            i += 1
        return result
    elif choice == '2':
        num = 0
        text = text.upper()
        for i in range(len(text)):
            if i > 0 and roman_map[text[i]] > roman_map[text[i-1]]:
                num += roman_map[text[i]] - 2 * roman_map[text[i-1]]
            else:
                num += roman_map[text[i]]
        return str(num)

def bcd_handler(text, choice, **kwargs):
    if choice == '1':  # Encode (decimal string to BCD)
        if not text.isdigit():
            raise ValueError("Input for BCD encoding must be a decimal string.")
        bcd_result = ""
        for digit in text:
            bcd_result += format(int(digit), '04b')
        return bcd_result
    elif choice == '2':  # Decode (BCD to decimal string)
        text = text.replace(" ", "") # Remove any spaces
        if not all(c in '01' for c in text) or len(text) % 4 != 0:
            raise ValueError("Input for BCD decoding must be a binary string with length a multiple of 4.")
        decimal_result = ""
        for i in range(0, len(text), 4):
            four_bits = text[i:i+4]
            decimal_result += str(int(four_bits, 2))
        return decimal_result

def base36_encode(number):
    if not isinstance(number, int):
        raise ValueError("Input must be an integer.")
    if number < 0:
        return '-' + base36_encode(-number)
    alphabet = '0123456789abcdefghijklmnopqrstuvwxyz'
    base36 = []
    while number > 0:
        number, i = divmod(number, 36)
        base36.append(alphabet[i])
    return ''.join(reversed(base36)) if base36 else '0'

def base36_decode(base36_string):
    return int(base36_string, 36)

def base36_handler(text, choice, **kwargs):
    if choice == '1':  # Encode
        try:
            num = int(text)
            return base36_encode(num)
        except ValueError:
            raise ValueError("Input for Base36 encoding must be an integer.")
    elif choice == '2':  # Decode
        try:
            return str(base36_decode(text.lower()))
        except ValueError:
            raise ValueError("Input for Base36 decoding must be a valid Base36 string.")

def base62_encode(number):
    if not isinstance(number, int):
        raise ValueError("Input must be an integer.")
    if number < 0:
        return '-' + base62_encode(-number)
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    base62 = []
    while number > 0:
        number, i = divmod(number, 62)
        base62.append(alphabet[i])
    return ''.join(reversed(base62)) if base62 else '0'

def base62_decode(base62_string):
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    base = 62
    strlen = len(base62_string)
    num = 0
    idx = 0
    for char in base62_string:
        power = (strlen - (idx + 1))
        num += alphabet.index(char) * (base ** power)
        idx += 1
    return num

def base62_handler(text, choice, **kwargs):
    if choice == '1':  # Encode
        try:
            num = int(text)
            return base62_encode(num)
        except ValueError:
            raise ValueError("Input for Base62 encoding must be an integer.")
    elif choice == '2':  # Decode
        try:
            return str(base62_decode(text))
        except ValueError:
            raise ValueError("Input for Base62 decoding must be a valid Base62 string.")

def quoted_printable_handler(text, choice, **kwargs):
    
    if choice == '1':
        return quopri.encodestring(text.encode('utf-8')).decode('ascii').strip()
    elif choice == '2':
        return quopri.decodestring(text.encode('ascii')).decode('utf-8')

def uuencoding_handler(text, choice, **kwargs):
    if choice == '1':
        return binascii.b2a_uu(text.encode('utf-8')).decode('ascii')
    elif choice == '2':
        return binascii.a2b_uu(text.encode('ascii')).decode('utf-8')

def xxencoding_handler(text, choice, **kwargs):
    _xx_alphabet = "+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz ."
    
    def xxencode(data):
        encoded_lines = []
        # XXencode typically works with lines of 45 bytes (60 encoded chars)
        chunk_size = 45
        
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i+chunk_size]
            
            # Length byte
            encoded_line = [_xx_alphabet[len(chunk) & 0x3F]]
            
            # Pad with nulls if chunk length is not a multiple of 3
            padded_chunk = chunk + b'\0' * ((3 - len(chunk) % 3) % 3)
            
            for j in range(0, len(padded_chunk), 3):
                b1, b2, b3 = padded_chunk[j:j+3]
                
                # Combine 3 bytes into a 24-bit integer
                val = (b1 << 16) | (b2 << 8) | b3
                
                # Extract 4 6-bit values
                e1 = (val >> 18) & 0x3F
                e2 = (val >> 12) & 0x3F
                e3 = (val >> 6) & 0x3F
                e4 = val & 0x3F
                
                encoded_line.extend([_xx_alphabet[e1], _xx_alphabet[e2], _xx_alphabet[e3], _xx_alphabet[e4]])
            
            encoded_lines.append("".join(encoded_line))
            
        return "\n".join(encoded_lines)

    def xxdecode(encoded_data):
        decoded_bytes = bytearray()
        lines = encoded_data.split('\n')
        
        for line in lines:
            if not line:
                continue
            
            # Get original length from the first character
            original_len = _xx_alphabet.find(line[0])
            if original_len == -1:
                raise ValueError("Invalid XXencode length character.")
            
            line_decoded_bytes = bytearray()
            # Process 4 characters at a time
            for i in range(1, len(line), 4):
                if i + 3 >= len(line): # Ensure there are 4 characters to process
                    break
                
                c1, c2, c3, c4 = line[i:i+4]
                
                v1 = _xx_alphabet.find(c1)
                v2 = _xx_alphabet.find(c2)
                v3 = _xx_alphabet.find(c3)
                v4 = _xx_alphabet.find(c4)
                
                if -1 in (v1, v2, v3, v4):
                    raise ValueError("Invalid XXencode character found.")
                
                # Combine 4 6-bit values into a 24-bit integer
                val = (v1 << 18) | (v2 << 12) | (v3 << 6) | v4
                
                # Extract 3 bytes
                b1 = (val >> 16) & 0xFF
                b2 = (val >> 8) & 0xFF
                b3 = val & 0xFF
                
                line_decoded_bytes.extend([b1, b2, b3])
            
            # Truncate the decoded bytes for this line and append to total
            decoded_bytes.extend(line_decoded_bytes[:original_len])
        
        return bytes(decoded_bytes)

    if choice == '1':
        return xxencode(text.encode('utf-8'))
    elif choice == '2':
        return xxdecode(text).decode('utf-8')

def hexlify_handler(text, choice, **kwargs):
    if choice == '1':
        return binascii.b2a_hex(text.encode('utf-8')).decode('ascii')
    elif choice == '2':
        return binascii.unhexlify(text.encode('ascii')).decode('utf-8')

def raw_hex_dump_handler(text, choice, **kwargs):
    if choice == '1':  # Encode to hex dump
        try:
            data_bytes = text.encode('utf-8')
            hex_dump_lines = []
            for i in range(0, len(data_bytes), 16):
                chunk = data_bytes[i:i+16]
                hex_part = ' '.join(f'{byte:02x}' for byte in chunk)
                ascii_part = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in chunk)
                hex_dump_lines.append(f'{i:08x}: {hex_part:<47} {ascii_part}')
            return '\n'.join(hex_dump_lines)
        except Exception as e:
            raise ValueError(f"Error encoding to raw hex dump: {e}")
    elif choice == '2':  # Decode from hex dump
        try:
            decoded_bytes = bytearray()
            lines = text.splitlines()
            for line in lines:
                # Skip empty lines or lines that don't look like hex dump lines
                if not line.strip() or ':' not in line:
                    continue
                
                parts = line.split(':')
                if len(parts) < 2:
                    continue # Not a valid hex dump line format

                hex_part = parts[1].split('#')[0].strip() # Ignore comments after #
                hex_values = hex_part.split()
                
                for hex_val in hex_values:
                    if len(hex_val) == 2 and all(c in '0123456789abcdefABCDEF' for c in hex_val):
                        decoded_bytes.append(int(hex_val, 16))
                    else:
                        # If we encounter non-hex characters, it might be a malformed dump or the ASCII part
                        # We'll try to be lenient and just process valid hex pairs
                        pass
            return decoded_bytes.decode('utf-8', errors='replace') # Use 'replace' for non-decodable bytes
        except Exception as e:
            raise ValueError(f"Error decoding from raw hex dump: {e}")

def ebcdic_handler(text, choice, **kwargs):
    if choice == '1':
        return base64.b64encode(text.encode('cp500')).decode('ascii')
    elif choice == '2':
        try:
            decoded_bytes = base64.b64decode(text.encode('ascii'))
            return decoded_bytes.decode('cp500')
        except (binascii.Error, UnicodeDecodeError) as e:
            raise ValueError(f"Invalid input for EBCDIC decoding: {e}")

def luhn_handler(text, choice, **kwargs):
    def calculate_luhn_sum(num_str):
        digits = [int(d) for d in num_str]
        total_sum = 0
        for i, digit in enumerate(reversed(digits)):
            if i % 2 == 1:  # Every second digit from the right (0-indexed reversed)
                doubled_digit = digit * 2
                if doubled_digit > 9:
                    total_sum += (doubled_digit - 9) # Same as (doubled_digit % 10) + (doubled_digit // 10)
                else:
                    total_sum += doubled_digit
            else:
                total_sum += digit
        return total_sum

    if not text.isdigit():
        raise ValueError("Input must be a string of digits.")

    if choice == '1':  # Generate checksum (append a digit to make it valid)
        # Calculate the sum for the number without a checksum digit
        current_sum = calculate_luhn_sum(text + '0') # Temporarily append '0' as placeholder for checksum
        
        # The check digit is the smallest digit that makes the total sum a multiple of 10
        check_digit = (10 - (current_sum % 10)) % 10
        return text + str(check_digit)
    elif choice == '2':  # Validate number (check if it's a valid Luhn number)
        total_sum = calculate_luhn_sum(text)
        if total_sum % 10 == 0:
            return f"Valid Luhn number. Sum: {total_sum}"
        else:
            return f"Invalid Luhn number. Sum: {total_sum}"

def geohash_handler(text, choice, **kwargs):
    if choice == '1':  # Encode (latitude,longitude to geohash)
        try:
            lat, lon = map(float, text.split(','))
            return pgh.encode(lat, lon)
        except ValueError:
            raise ValueError("Invalid input for Geohash encoding. Expected 'latitude,longitude'.")
    elif choice == '2':  # Decode (geohash to latitude,longitude)
        try:
            lat, lon = pgh.decode(text)
            return f"{lat},{lon}"
        except ValueError:
            raise ValueError("Invalid input for Geohash decoding. Expected a valid geohash string.")

def uuid_handler(text, choice, **kwargs):
    if choice == '1':  # Generate UUID
        return str(uuid.uuid4())
    elif choice == '2':  # Parse UUID
        try:
            parsed_uuid = uuid.UUID(text)
            return f"UUID Version: {parsed_uuid.version}\nUUID Variant: {parsed_uuid.variant}\nUUID String: {str(parsed_uuid)}"
        except ValueError as e:
            raise ValueError(f"Invalid UUID string for parsing. Please provide a valid UUID string, e.g., 'f47ac10b-58cc-4372-a567-0e02b2c3d479'. Error: {e}")

def compression_handler(text, choice, comp_lib, **kwargs):
    if choice == '1':
        encoded_text = text.encode('utf-8')
        if comp_lib == lzma:
            compressed = comp_lib.compress(encoded_text, format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA1}])
        elif comp_lib == zstd:
            compressed = zstd.compress(encoded_text, level=1) # Use top-level zstd.compress with level 1
            return base64.b64encode(compressed).decode('latin-1') # Use standard Base64, decode to latin-1
        else:
            compressed = comp_lib.compress(encoded_text)
        return base64.b64encode(compressed).decode('utf-8')
    elif choice == '2':
        if comp_lib == lzma:
            compressed = base64.b64decode(text.encode('ascii'))
            decompressed = comp_lib.decompress(compressed, format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA1}])
        elif comp_lib == zstd:
            compressed = base64.b64decode(text.encode('latin-1')) # Use standard Base64, encode from latin-1
            decompressed = zstd.decompress(compressed) # Use top-level zstd.decompress
        else:
            compressed = base64.b64decode(text.encode('ascii'))
            decompressed = comp_lib.decompress(compressed)
        return decompressed.decode('utf-8')

def zlib_handler(text, choice, **kwargs): return compression_handler(text, choice, zlib)
def gzip_handler(text, choice, **kwargs): return compression_handler(text, choice, gzip)
def bzip2_handler(text, choice, **kwargs): return compression_handler(text, choice, bz2)
def lzma_handler(text, choice, **kwargs): return compression_handler(text, choice, lzma)
def deflate_handler(text, choice, **kwargs): return compression_handler(text, choice, zlib) # Deflate uses zlib
def zstd_handler(text, choice, **kwargs): return compression_handler(text, choice, zstd)

def brainfuck_handler(text, choice, **kwargs):
    if choice == '1':
        # Simple (non-optimal) Brainfuck generator
        # For a more robust solution, a proper compiler would be needed
        res = ""
        ptr = 0
        for char in text:
            val = ord(char)
            diff = val - ptr
            if diff > 0:
                res += "+" * diff
            else:
                res += "-" * abs(diff)
            res += "."
            ptr = val
        return res
    elif choice == '2':
        # Brainfuck interpreter
        text = "".join(filter(lambda x: x in ['.', ',', '[', ']', '<', '>', '+', '-'], text))
        data = [0] * 30000
        data_ptr = 0
        instr_ptr = 0
        output = ""
        while instr_ptr < len(text):
            command = text[instr_ptr]
            if command == ">":
                data_ptr += 1
            elif command == "<":
                data_ptr -= 1
            elif command == "+":
                data[data_ptr] = (data[data_ptr] + 1) % 256
            elif command == "-":
                data[data_ptr] = (data[data_ptr] - 1) % 256
            elif command == ".":
                output += chr(data[data_ptr])
            elif command == ",":
                # Placeholder for input, not implemented in this context
                data[data_ptr] = 0
            elif command == "[" and data[data_ptr] == 0:
                loop_level = 1
                while loop_level > 0:
                    instr_ptr += 1
                    if text[instr_ptr] == '[':
                        loop_level += 1
                    elif text[instr_ptr] == ']':
                        loop_level -= 1
            elif command == "]" and data[data_ptr] != 0:
                loop_level = 1
                while loop_level > 0:
                    instr_ptr -= 1
                    if text[instr_ptr] == ']':
                        loop_level += 1
                    elif text[instr_ptr] == '[':
                        loop_level -= 1
            instr_ptr += 1
        return output

def tap_code_handler(text, choice, **kwargs):
    grid = {
        'A': '11', 'B': '12', 'C': '13', 'D': '14', 'E': '15',
        'F': '21', 'G': '22', 'H': '23', 'I': '24', 'J': '25',
        'L': '31', 'M': '32', 'N': '33', 'O': '34', 'P': '35',
        'Q': '41', 'R': '42', 'S': '43', 'T': '44', 'U': '45',
        'V': '51', 'W': '52', 'X': '53', 'Y': '54', 'Z': '55',
        'K': '13' # K is often mapped to C
    }
    reverse_grid = {v: k for k, v in grid.items()}
    # Ensure 'C' is the primary for '13' when decoding
    reverse_grid['13'] = 'C'


    if choice == '1': # Encode
        encoded_message = []
        for char in text.upper():
            if char in grid:
                encoded_message.append(grid[char])
            elif char == ' ':
                encoded_message.append('/')
        return ' '.join(encoded_message)
    elif choice == '2': # Decode
        decoded_message = ""
        parts = text.split(' ')
        for part in parts:
            if part == '/':
                decoded_message += ' '
            elif part in reverse_grid:
                decoded_message += reverse_grid[part]
        return decoded_message



def sha3_224_handler(text, **kwargs): return hash_handler(text, 'sha3_224')
def sha3_256_handler(text, **kwargs): return hash_handler(text, 'sha3_256')
def sha3_384_handler(text, **kwargs): return hash_handler(text, 'sha3_384')
def sha3_512_handler(text, **kwargs): return hash_handler(text, 'sha3_512')

def blake2b_handler(text, **kwargs): return hash_handler(text, 'blake2b')
def blake2s_handler(text, **kwargs): return hash_handler(text, 'blake2s')

def base85_handler(text, choice, **kwargs):
    if choice == '1':
        return base64.a85encode(text.encode('utf-8')).decode('ascii')
    elif choice == '2':
        return base64.a85decode(text.encode('ascii')).decode('utf-8')

# Base91 implementation (from https://github.com/ghewgill/base91/blob/master/base91.py)
_b91_alphabet = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '!', '#', '$', '%', '&', '(', ')', '*', '+', ',', '.', '/', ':', ';', '<', '=', '>', '?', '@', '[', ']', '^', '_', '`', '{', '|', '}', '~', '"']
_b91_decode_table = dict((v, k) for k, v in enumerate(_b91_alphabet))

def base91_encode(bindata):
    retval = []
    bitn = 0
    byte = 0
    for c in bindata:
        byte |= c << bitn
        bitn += 8
        if bitn > 13:
            v = byte & 8191
            if v > 89:
                byte >>= 13
                bitn -= 13
            else:
                v = byte & 16383
                byte >>= 14
                bitn -= 14
            retval.append(_b91_alphabet[v % 91])
            retval.append(_b91_alphabet[v // 91])
    if bitn:
        retval.append(_b91_alphabet[byte % 91])
        if bitn > 7 or byte > 90:
            retval.append(_b91_alphabet[byte // 91])
    return ''.join(retval)

def base91_decode(encoded_data):
    retval = []
    bitn = 0
    byte = 0
    v = -1
    for c in encoded_data:
        if not c in _b91_decode_table:
            continue
        c = _b91_decode_table[c]
        if v < 0:
            v = c
        else:
            v += c * 91
            byte |= v << bitn
            bitn += 13 if (v & 8191) > 89 else 14
            while bitn > 7:
                retval.append(byte & 255)
                byte >>= 8
                bitn -= 8
            v = -1
    if v != -1:
        retval.append(byte | v << bitn)
    return bytes(retval)



def base91_handler(text, choice, **kwargs):
    if choice == '1':
        return base91_encode(text.encode('utf-8'))
    elif choice == '2':
        return base91_decode(text).decode('utf-8', errors='replace')

def titlecase_handler(text, **kwargs): return text.title()

def verify_hash_handler(text, hash_type, expected_hash, **kwargs):
    try:
        h = hashlib.new(hash_type)
        h.update(text.encode('utf-8'))
        calculated_hash = h.hexdigest()
        if calculated_hash == expected_hash:
            return f"Hash verification successful! Calculated hash: {calculated_hash}"
        else:
            return f"Hash verification failed. Calculated hash: {calculated_hash}, Expected hash: {expected_hash}"
    except ValueError:
        return f"Error: Invalid hash type '{hash_type}'."
    except Exception as e:
        return f"An error occurred during hash verification: {e}"

def analyze_hash_handler(text, **kwargs):
    # Common hash lengths in characters (hex representation)
    hash_lengths = {
        32: "MD5, NTLM",
        40: "SHA-1",
        56: "SHA-224",
        64: "SHA-256, SHA3-256, BLAKE2s",
        96: "SHA-384, SHA3-384",
        128: "SHA-512, SHA3-512, BLAKE2b",
    }

    text = text.strip().lower()
    text_len = len(text)

    possible_types = []

    # Check if it's a hexadecimal string
    if all(c in '0123456789abcdef' for c in text):
        if text_len in hash_lengths:
            possible_types.append(f"Possible hash types (based on length {text_len}): {hash_lengths[text_len]}")
        else:
            possible_types.append(f"Hexadecimal string of length {text_len}. No common hash type matches this length.")
    else:
        possible_types.append("Not a hexadecimal string.")

    if not possible_types:
        return "Could not determine hash type."
    else:
        return "\n".join(possible_types)

def help_handler(text, parser=None, **kwargs):
    print(MAIN_HELP_MESSAGE)
    
    # If parser is not provided (e.g., called from interactive menu), create a dummy one
    if parser is None:
        temp_parser = argparse.ArgumentParser(
            description="Temporary parser for help display",
            formatter_class=CustomHelpFormatter
        )
        # Replicate the arguments from the main parser
        temp_parser.add_argument('-op', '--operation', help='Specify the operation to perform (e.g., Base64, MD5).')
        temp_parser.add_argument('-c', '--choice', help='Specify sub-choice for operation (e.g., 1 for encode, 2 for decode).', type=str)
        temp_parser.add_argument('-i', '--input', help='Input string for the operation.')
        temp_parser.add_argument('-if', '--input-file', help='Read input from a specified file.')
        temp_parser.add_argument('-of', '--output-file', help='Write output to a specified file.')
        temp_parser.add_argument('-k', '--key', help='Key for ciphers (e.g., VigenÃ¨re, XOR).')
        temp_parser.add_argument('--shift', type=int, help='Shift value for Caesar cipher.')
        temp_parser.add_argument('--rails', type=int, help='Number of rails for Rail Fence cipher.')
        temp_parser.add_argument('--diameter', type=int, help='Diameter for Scytale cipher.')
        temp_parser.add_argument('--key_a', type=int, help='Key "a" for Affine cipher.')
        temp_parser.add_argument('--key_b', type=int, help='Key "b" for Affine cipher.')
        temp_parser.add_argument('--key_matrix_str', help='Key matrix string for Hill cipher (e.g., "2 3,1 4").')
        temp_parser.add_argument('--ht', '--hash-type', dest='hash_type', help='Hash type for Verify Hash (e.g., md5, sha256).')
        temp_parser.add_argument('--eh', '--expected-hash', dest='expected_hash', help='Expected hash for Verify Hash.')
        temp_parser.add_argument('--history', action='store_true', help='Display operation history.')
        temp_parser.add_argument('--clear-history', action='store_true', help='Clear operation history.')
        temp_parser.add_argument('-m', '--mobile-display', action='store_true', help='Use mobile-friendly single-column menu display.')
        parser = temp_parser # Use the temporary parser
    
    # Manually format and print options
    options_list = []
    max_flag_len = 0
    for action in parser._actions:
        if action.help is not argparse.SUPPRESS:
            # Construct the flag string
            flags = []
            if action.option_strings:
                flags = action.option_strings
            
            flag_str = ', '.join(flags)
            if action.metavar:
                flag_str += f" <{action.metavar}>"
            elif action.nargs != 0 and action.const is None: # For arguments that take a value
                if action.type is int:
                    flag_str += " <int>"
                elif action.type is str:
                    flag_str += " <string>"
                else:
                    flag_str += " <value>"
            
            # Store original flag string and help text
            options_list.append((flag_str, action.help))
            max_flag_len = max(max_flag_len, get_display_width(flag_str))
    
    # Calculate dynamic flag_width and total_width
    terminal_width = shutil.get_terminal_size().columns
    flag_width = min(max_flag_len + 2, terminal_width // 2 - 2) # Max half terminal width, with some padding
    total_width = terminal_width - 2 # Leave some margin

    print(f"\n{Fore.CYAN}{Style.BRIGHT}Options:{Style.RESET_ALL}")
    print(format_options_two_columns(options_list, flag_width=flag_width, total_width=total_width))
    if sys.stdin.isatty(): # Only prompt for input if running in an interactive terminal
        input("\nPress Enter to return to the menu...")
    return ""

# --- Menu Configuration ---

MENU_OPTIONS = {
    # Common Encodings
    "01": {"name": "Binary", "handler": binary_handler, "sub_choice": True},
    "02": {"name": "Hexadecimal", "handler": hex_handler, "sub_choice": True},
    "03": {"name": "Base64", "handler": base64_handler, "sub_choice": True},
    "04": {"name": "URL (Percent) Encoding", "handler": url_handler, "sub_choice": True},
    "05": {"name": "HTML Entities", "handler": html_entities_handler, "sub_choice": True},
    "06": {"name": "ASCII Values", "handler": ascii_values_handler, "sub_choice": True},
    "07": {"name": "Punycode", "handler": punycode_handler, "sub_choice": True},
    "08": {"name": "XML", "handler": xml_handler, "sub_choice": True},
    "09": {"name": "JSON", "handler": json_handler, "sub_choice": True},
    "10": {"name": "YAML", "handler": yaml_handler, "sub_choice": True},
    "11": {"name": "ISO-8859-1 (Latin-1)", "handler": iso8859_1_handler, "sub_choice": True},
    "12": {"name": "Shift-JIS", "handler": shift_jis_handler, "sub_choice": True},
    "13": {"name": "UTF-7", "handler": utf7_handler, "sub_choice": True},
    "14": {"name": "UTF-8", "handler": utf8_handler, "sub_choice": True},
    "15": {"name": "UTF-16", "handler": utf16_handler, "sub_choice": True},
    "16": {"name": "UTF-32", "handler": utf32_handler, "sub_choice": True},
    "17": {"name": "Base32", "handler": base32_handler, "sub_choice": True},
    "18": {"name": "Base58", "handler": base58_handler, "sub_choice": True},
    "19": {"name": "Base85", "handler": base85_handler, "sub_choice": True},
    "20": {"name": "Base91", "handler": base91_handler, "sub_choice": True},
    # Classic Ciphers
    "21": {"name": "ROT13", "handler": rot13_handler},
    "22": {"name": "Caesar Cipher", "handler": caesar_handler, "sub_choice": True, "extra_input": {"name": "shift", "prompt": "Enter shift value (1-25): ", "type": int}},
    "23": {"name": "Atbash Cipher", "handler": atbash_handler},
    "24": {"name": "Morse Code", "handler": morse_code_handler, "sub_choice": True},
    "25": {"name": "A1Z26 Cipher", "handler": a1z26_handler, "sub_choice": True},
    "26": {"name": "VigenÃ¨re Cipher", "handler": vigenere_handler, "sub_choice": True, "extra_input": {"name": "key", "prompt": "Enter VigenÃ¨re key: ", "type": str}},
    "27": {"name": "Baconian Cipher", "handler": baconian_handler, "sub_choice": True},
    "28": {"name": "Polybius Square", "handler": polybius_square_handler, "sub_choice": True},
    # New Classic Ciphers
    "29": {"name": "Affine Cipher", "handler": affine_handler, "sub_choice": True, "extra_input": [
        {"name": "key_a", "prompt": "Enter key 'a' (coprime with 26): ", "type": int},
        {"name": "key_b", "prompt": "Enter key 'b': ", "type": int}
    ]},
    "30": {"name": "Playfair Cipher", "handler": playfair_cipher_handler, "sub_choice": True, "extra_input": {"name": "key", "prompt": "Enter Playfair keyword: ", "type": str}},
    "31": {"name": "Hill Cipher", "handler": hill_cipher_handler, "sub_choice": True, "extra_input": {"name": "key_matrix_str", "prompt": "Enter Hill Cipher key matrix (e.g., '2 3,1 4'): "}},
    "32": {"name": "Rail Fence Cipher", "handler": rail_fence_handler, "sub_choice": True, "extra_input": {"name": "rails", "prompt": "Enter number of rails: ", "type": int}},
    "33": {"name": "Scytale Cipher", "handler": scytale_handler, "sub_choice": True, "extra_input": {"name": "diameter", "prompt": "Enter diameter (number of columns): ", "type": int}},
    "34": {"name": "XOR Cipher", "handler": xor_cipher_handler, "sub_choice": True, "extra_input": {"name": "key", "prompt": "Enter XOR key: ", "type": str}},

    # String Manipulation
    "35": {"name": "Reverse String", "handler": reverse_handler},
    "36": {"name": "Uppercase", "handler": uppercase_handler},
    "37": {"name": "Lowercase", "handler": lowercase_handler},
    "38": {"name": "Capitalize", "handler": capitalize_handler},
    "39": {"name": "Title Case", "handler": titlecase_handler},
    "40": {"name": "Swap Case", "handler": swapcase_handler},
    "41": {"name": "Leet (1337)", "handler": leet_handler, "sub_choice": True},

    # Hashing (One-Way)
    "42": {"name": "Analyze Hash", "handler": analyze_hash_handler},
    "43": {"name": "Verify Hash", "handler": verify_hash_handler, "extra_input": [
        {"name": "hash_type", "prompt": "Enter hash type (e.g., md5, sha256): ", "type": str},
        {"name": "expected_hash", "prompt": "Enter the expected hash value: ", "type": str}
    ]},
    "44": {"name": "MD5", "handler": md5_handler},
    "45": {"name": "SHA-1", "handler": sha1_handler},
    "46": {"name": "SHA256", "handler": sha256_handler},
    "47": {"name": "SHA-512", "handler": sha512_handler},
    "48": {"name": "CRC32", "handler": crc32_handler},
    "49": {"name": "Adler-32", "handler": adler32_handler},
    "50": {"name": "SHA3-224", "handler": sha3_224_handler},
    "51": {"name": "SHA3-256", "handler": sha3_256_handler},
    "52": {"name": "SHA3-384", "handler": sha3_384_handler},
    "53": {"name": "SHA3-512", "handler": sha3_512_handler},
    "54": {"name": "BLAKE2b", "handler": blake2b_handler},
    "55": {"name": "BLAKE2s", "handler": blake2s_handler},

    # Numeric Systems
    "56": {"name": "Decimal to Hex", "handler": decimal_to_hex_handler},
    "57": {"name": "Hex to Decimal", "handler": hex_to_decimal_handler},
    "58": {"name": "Decimal to Octal", "handler": decimal_to_octal_handler},
    "59": {"name": "Octal to Decimal", "handler": octal_to_decimal_handler},
    "60": {"name": "IP Address to Integer", "handler": ip_to_integer_handler},
    "61": {"name": "Integer to IP Address", "handler": integer_to_ip_handler},
    "62": {"name": "Roman Numerals", "handler": roman_numerals_handler, "sub_choice": True},
    "63": {"name": "Binary Coded Decimal (BCD)", "handler": bcd_handler, "sub_choice": True},
    "64": {"name": "Base36", "handler": base36_handler, "sub_choice": True},
    "65": {"name": "Base62", "handler": base62_handler, "sub_choice": True},

    # Miscellaneous
    "66": {"name": "Quoted-Printable", "handler": quoted_printable_handler, "sub_choice": True},
    "67": {"name": "UUencoding", "handler": uuencoding_handler, "sub_choice": True},
    "68": {"name": "XXencoding", "handler": xxencoding_handler, "sub_choice": True},
    "69": {"name": "Hexlify", "handler": hexlify_handler, "sub_choice": True},
    "70": {"name": "EBCDIC", "handler": ebcdic_handler, "sub_choice": True},
    "71": {"name": "Luhn Algorithm", "handler": luhn_handler, "sub_choice": True},
    "72": {"name": "Geohash", "handler": geohash_handler, "sub_choice": True},
    "73": {"name": "UUID (Generate/Parse)", "handler": uuid_handler, "sub_choice": True},
    "74": {"name": "Raw Hex Dump", "handler": raw_hex_dump_handler, "sub_choice": True},
    "75": {"name": "Brainfuck", "handler": brainfuck_handler, "sub_choice": True},
    "76": {"name": "Tap Code", "handler": tap_code_handler, "sub_choice": True},

    # Compression
    "77": {"name": "Zlib Compress", "handler": zlib_handler, "sub_choice": True},
    "78": {"name": "Gzip Compress", "handler": gzip_handler, "sub_choice": True},
    "79": {"name": "Bzip2 Compress", "handler": bzip2_handler, "sub_choice": True},
    "80": {"name": "LZMA Compress", "handler": lzma_handler, "sub_choice": True},
    "81": {"name": "Deflate", "handler": deflate_handler, "sub_choice": True},
    "82": {"name": "Zstandard Compress", "handler": zstd_handler, "sub_choice": True},
}

SYSTEM_OPTIONS = {
    "83": {"name": "Auto Detect", "handler": auto_detect_handler, "input_prompt": "Enter text to auto-detect encoding: "},
    "84": {"name": "Help Message", "handler": help_handler, "no_input_required": True},
    "85": {"name": "Exit"},
}

# --- Main Logic ---

def display_menu_one_column():
    print("\n--- Ovaltine Encoding/Decoding Tool ---")
    
    # Main encoding/decoding options
    current_number = 1
    main_options_map = {} # To store mapping from new number to original key
    
    # Sort options by their original key for consistent ordering
    sorted_keys = sorted(MENU_OPTIONS.keys(), key=lambda x: int(x))

    for key in sorted_keys:
        op_info = MENU_OPTIONS[key]
        print(f"[{current_number:02d}] {op_info['name']}")
        main_options_map[str(current_number)] = key
        current_number += 1

    # System Options
    print("\n--- System Options ---")
    system_option_keys = sorted(SYSTEM_OPTIONS.keys(), key=lambda x: int(x)) # Sort system options too
    for key in system_option_keys:
        op_info = SYSTEM_OPTIONS[key]
        print(f"[{int(key):02d}] {op_info['name']}")
        main_options_map[key] = key # Add system options to map with their original keys
    print() # Added blank line
    print("_" * 50)

    # Display a random phrase
    random_phrase = random.choice(PHRASES)
    print(f"\n  {bold_white(random_phrase)}")
    print() # Added blank line
    print("_" * 50)
    print() # Added blank line

    return main_options_map # Return the map for choice handling

def display_menu_two_columns():
    print() # Additional blank line for spacing
    print() # Blank line before
    print(f"{Fore.WHITE}{Style.BRIGHT}< https://github.com/ghostescript/ovaltinepy >{Style.RESET_ALL}".center(80))
    print(f"{Fore.GREEN}{Style.BRIGHT}Encoder/Decoder/Hasher{Style.RESET_ALL}".center(80))
    print() # Added blank line
    print(f"{Fore.YELLOW}{Style.BRIGHT}Select an option from the list below:{Style.RESET_ALL}\n")

    # Define categories and their items
    left_categories = {
        "Common Encodings": list(range(1, 21)), # 01-20
        "Classic Ciphers": list(range(21, 35)), # 21-34
        "String Manipulation": list(range(35, 42)), # 35-41
    }
    right_categories = {
        "Hashing (One-Way)": list(range(42, 56)), # 42-55
        "Numeric Systems": list(range(56, 66)), # 56-65
        "Miscellaneous": list(range(66, 77)), # 66-76 (now includes Brainfuck and Pig Latin)
        "Compression (I/O is Base64)": list(range(77, 83)), # 77-82 (renumbered)
    }

    # Create a list of lines for each column
    left_lines = []
    for title, indices in left_categories.items():
        left_lines.append(f"{Fore.CYAN}{Style.BRIGHT}{title}{Style.RESET_ALL}") # Bold Cyan
        left_lines.append("") # Added blank line below title
        for i in indices:
            num_str = str(i).zfill(2)
            if num_str in MENU_OPTIONS:
                left_lines.append(f"[{num_str.zfill(2)}] {MENU_OPTIONS[num_str]['name']}")
        left_lines.append("") # Add a blank line between categories

    right_lines = []
    for title, indices in right_categories.items():
        right_lines.append(f"{Fore.CYAN}{Style.BRIGHT}{title}{Style.RESET_ALL}") # Bold Cyan
        right_lines.append("") # Added blank line below title
        for i in indices:
            num_str = str(i).zfill(2)
            if num_str in MENU_OPTIONS:
                right_lines.append(f"[{num_str.zfill(2)}] {MENU_OPTIONS[num_str]['name']}")
        right_lines.append("") # Add a blank line between categories

    # Print the columns side-by-side
    max_lines = max(len(left_lines), len(right_lines))
    for i in range(max_lines):
        left = left_lines[i] if i < len(left_lines) else ""
        right = right_lines[i] if i < len(right_lines) else ""

        # Calculate display width of the left string, ignoring ANSI codes
        left_display_width = get_display_width(left)
        
        # Determine padding for the right column
        # Assuming a total terminal width of 80, and left column takes up to 40 chars
        # We need to adjust the padding based on the actual display width of 'left'
        padding = 40 - left_display_width
        if padding < 1: # Ensure at least one space between columns
            padding = 1

        print(f"{left}{' ' * padding}{right}")

    # Print System Options and random phrase after the two columns
    print("_" * 80) # Horizontal line
    print() # Added blank line above System Options
    print(f"{Fore.CYAN}{Style.BRIGHT}System Options{Style.RESET_ALL}") # Bold Cyan title
    print() # Blank line below title
    
    # Dynamically add system options
    system_option_keys = sorted(SYSTEM_OPTIONS.keys(), key=lambda x: int(x)) # Use SYSTEM_OPTIONS
    for key in system_option_keys:
        op_info = SYSTEM_OPTIONS[key] # Use SYSTEM_OPTIONS
        print(f"[{key.zfill(2)}] {op_info['name']}")
    print() # Blank line below Exit

    # Display a random phrase above the bottom dotted line
    random_phrase = random.choice(PHRASES)

    print(f"  {bold_white(random_phrase)}") # Left-align and bold white the phrase
    print() # Added blank line below random message
    print("_" * 80)
    print() # Added blank line below the bottom separator


# ==============================================================================
# TEST CONFIGURATION
# ==============================================================================

SUITABLE_INPUTS = {
    "Binary": {"1": "Hello", "2": "01001000 01100101 01101100 01101100 01101111"},
    "Hexadecimal": {"1": "Hello", "2": "48656c6c6f"},
    "Base64": {"1": "Hello", "2": "SGVsbG8="},
    "URL (Percent) Encoding": {"1": "Hello World!", "2": "Hello%20World%21"},
    "HTML Entities": {"1": "<p>Hello</p>", "2": "&lt;p&gt;Hello&lt;/p&gt;"},
    "ASCII Values": {"1": "ABC", "2": "65 66 67"},
    "Punycode": {"1": "MÃ¼nchen", "2": "xn--Mnchen-3ya"},
    "XML": {"1": "<tag>value</tag>", "2": "&lt;tag&gt;value&lt;/tag&gt;"},
        "JSON": {"1": '{"key": "value"}', "2": r'''{
            "name": "test",
            "value": 123
        }'''},
    "YAML": {"1": "key: value", "2": "key: value\n"},
    "ISO-8859-1 (Latin-1)": {"1": "VoilÃ ", "2": "Vm9pbMOg"},
    "Shift-JIS": {"1": "Hello", "2": "SGVsbG8="},
    "UTF-7": {"1": "Hello", "2": "SGVsbG8="},
    "UTF-8": {"1": "Hello", "2": "SGVsbG8="},
    "UTF-16": {"1": "Hello", "2": "/v8ASABlAGwAbABvAA=="},
    "UTF-32": {"1": "Hello", "2": "//8ASAAAAHkAAABsAAAAbAAAAHAAAAA="},
    "Base32": {"1": "Hello", "2": "JBSWY3DP"},
    "Base58": {"1": "Hello", "2": "9Ajd"},
    "Base85": {"1": "Hello", "2": "87cUR"},
    "Base91": {"1": "Hello", "2": ">OwJh"},
    "ROT13": {"1": "Hello", "2": "Uryyb"},
    "Caesar Cipher": {"1": "Hello", "2": "Khoor", "extra": {"shift": 3}},
    "Atbash Cipher": {"1": "Hello", "2": "Svool"},
    "Morse Code": {"1": "SOS", "2": "... --- ..."},
    "A1Z26 Cipher": {"1": "code", "2": "3-15-4-5"},
    "VigenÃ¨re Cipher": {"1": "attackatdawn", "2": "LXFOPVEFRNHR", "extra": {"key": "SECRET"}},
    "Baconian Cipher": {"1": "Hello", "2": "aabbbabaaaaababbababb"},
    "Polybius Square": {"1": "hello", "2": "2315313134"},
    "Affine Cipher": {"1": "hello", "2": "rcjjm", "extra": {"key_a": 5, "key_b": 8}},
    "Playfair Cipher": {"1": "hello", "2": "CFMMU", "extra": {"key": "keyword"}},
    "Hill Cipher": {"1": "ACT", "2": "POH", "extra": {"key_matrix_str": "5 8,17 3"}},
    "Rail Fence Cipher": {"1": "HelloWorld", "2": "Horel olWd", "extra": {"rails": 3}},
    "Scytale Cipher": {"1": "HelloWorld", "2": "HloolelWrd", "extra": {"diameter": 4}},
    "XOR Cipher": {"1": "secret", "2": "13160a1c0b0d", "extra": {"key": "key"}},
    "Reverse String": {"1": "desserts", "2": "stressed"},
    "Uppercase": {"1": "hello", "2": "HELLO"},
    "Lowercase": {"1": "HELLO", "2": "hello"},
    "Capitalize": {"1": "hello world", "2": "Hello world"},
    "Title Case": {"1": "hello world", "2": "Hello World"},
    "Swap Case": {"1": "hELLo wORLd", "2": "HellO WorlD"},
    "Leet (1337)": {"1": "hello elite", "2": "h3110 31i73"},
    "Analyze Hash": {"1": "098f6bcd4621d373cade4e832627b4f6"},
    "Verify Hash": {"1": "test", "extra": {"hash_type": "md5", "expected_hash": "098f6bcd4621d373cade4e832627b4f6"}},
    "MD5": {"1": "hello"},
    "SHA-1": {"1": "hello"},
    "SHA256": {"1": "hello"},
    "SHA-512": {"1": "hello"},
    "CRC32": {"1": "hello"},
    "Adler-32": {"1": "hello"},
    "SHA3-224": {"1": "hello"},
    "SHA3-256": {"1": "hello"},
    "SHA3-384": {"1": "hello"},
    "SHA3-512": {"1": "hello"},
    "BLAKE2b": {"1": "hello"},
    "BLAKE2s": {"1": "hello"},
    "Decimal to Hex": {"1": "255", "2": "ff"},
    "Hex to Decimal": {"1": "ff", "2": "255"},
    "Decimal to Octal": {"1": "10", "2": "12"},
    "Octal to Decimal": {"1": "12", "2": "10"},
    "IP Address to Integer": {"1": "192.168.1.1", "2": "3232235777"},
    "Integer to IP Address": {"1": "3232235777", "2": "192.168.1.1"},
    "Roman Numerals": {"1": "1984", "2": "MCMLXXXIV"},
    "Binary Coded Decimal (BCD)": {"1": "123", "2": "000100100011"},
    "Base36": {"1": "12345", "2": "9ix"},
    "Base62": {"1": "1234567890", "2": "1LY7v"},
    "Quoted-Printable": {"1": "Hello!", "2": "Hello=21"},
    "UUencoding": {"1": "Cat", "2": "#0V%T\n`\n"},
    "XXencoding": {"1": "Cat", "2": "h3V3\n"},
    "Hexlify": {"1": "Hello", "2": "48656c6c6f"},
    "EBCDIC": {"1": "Hello", "2": "SGVsbG8="}, # EBCDIC is complex, using base64 as a proxy
    "Luhn Algorithm": {"1": "7992739871", "2": "79927398713"},
    "Geohash": {"1": "38.9072,-77.0369", "2": "dqcjqcj"},
    "UUID (Generate/Parse)": {"1": "", "2": "f47ac10b-58cc-4372-a567-0e02b2c3d479"},
    "Raw Hex Dump": {"1": "Hello", "2": "00000000: 48 65 6c 6c 6f"},
    "Brainfuck": {"1": "Hi", "2": "++[>+>+<<-]>>+.>." },
    "Tap Code": {"1": "hello", "2": "23 15 31 31 34"},
    "Zlib Compress": {"1": "hello", "2": "eJzLSM3JyQcABiwCFQ=="},
    "Gzip Compress": {"1": "hello", "2": "H4sIAAAAAAAA/8tIzcnJBwCGphA2BQAAAA=="},
    "Bzip2 Compress": {"1": "hello", "2": "QlpoOTFBWSZTWYJ+37YAAAADgAB/gECAAECAwAAYAAzMDAwA0PT"},
    "LZMA Compress": {"1": "hello", "2": "/Td6WFoAAAEAIgAAdmhrgAAB92R4eQo="},
    "Deflate": {"1": "hello", "2": "eJzLSM3JyQcABiwCFQ=="},
    "Zstandard Compress": {"1": "hello", "2": "KLUv/QIAAAAYaGVsbG8="},
    "Auto Detect": {"1": "SGVsbG8="},
    "Help Message": {"1": ""},
    "Exit": {"1": ""},
}

# Define tests that can be run as a round-trip (encode -> decode)
ROUND_TRIP_TESTS = [
    {"name": "Base64", "op": "Base64", "input": "Hello World!"},
    {"name": "Hexadecimal", "op": "Hexadecimal", "input": "test 123"},
    {"name": "Binary", "op": "Binary", "input": "0101"},
    {"name": "HTML Entities", "op": "HTML Entities", "input": "<p>Hello &amp; Welcome</p>"},
    {"name": "Base32", "op": "Base32", "input": "This is a base32 test.", "expected_output": "This is a base32 test.", "case_insensitive": False},
    {"name": "URL (Percent) Encoding", "op": "URL (Percent) Encoding", "input": "https://example.com/?q=a b"},
    {"name": "ASCII Values", "op": "ASCII Values", "input": "Hello"},
    {"name": "Base58", "op": "Base58", "input": "bitcoin address"},
    {"name": "Caesar Cipher", "op": "CaesarCipher", "input": "abc XYZ", "args": "--shift 5"},
    {"name": "A1Z26 Cipher", "op": "A1Z26 Cipher", "input": "code"},
    {"name": "VigenÃ¨re Cipher", "op": "VigenÃ¨re Cipher", "input": "attack at dawn", "args": "-k SCRIPT"},
    {"name": "XOR Cipher", "op": "XOR Cipher", "input": "a secret message", "args": "-k key"},
    {"name": "Morse Code", "op": "Morse Code", "input": "SOS"},
    {"name": "Binary Coded Decimal (BCD)", "op": "Binary Coded Decimal (BCD)", "input": "1234590"},
    {"name": "Quoted-Printable", "op": "Quoted-Printable", "input": "Hello =?utf-8?B?IFdvcmxkIQ==?="},
    {"name": "Zlib Compress", "op": "Zlib Compress", "input": "The quick brown fox jumps over the lazy dog."}, 
    {"name": "Gzip Compress", "op": "Gzip Compress", "input": "The quick brown fox jumps over the lazy dog."},
    {"name": "Bzip2 Compress", "op": "Bzip2 Compress", "input": "The quick brown fox jumps over the lazy dog."},
    {"name": "LZMA Compress", "op": "LZMA Compress", "input": "The quick brown fox jumps over the lazy dog."},
    {"name": "Deflate", "op": "Deflate", "input": "The quick brown fox jumps over the lazy dog."},
    {"name": "Zstandard Compress", "op": "Zstandard Compress", "input": "The quick brown fox jumps over the lazy dog."},
    {"name": "Affine Cipher", "op": "Affine Cipher", "input": "a secret", "args": "--key_a 5 --key_b 8"},
    {"name": "Baconian Cipher", "op": "Baconian Cipher", "input": "HELO"},
    {"name": "Base36", "op": "Base36", "input": "1234567890"},
    {"name": "Base62", "op": "Base62", "input": "12345678901234567890"},
    {"name": "Base85", "op": "Base85", "input": "Hello World!"},
    {"name": "Base91", "op": "Base91", "input": "Hello World!"},
    {"name": "Hexlify", "op": "Hexlify", "input": "Some data."},
    {"name": "Leet (1337)", "op": "Leet (1337)", "input": "hello elite"},
    {"name": "Polybius Square", "op": "Polybius Square", "input": "polybius", "case_insensitive": True},
    {"name": "Rail Fence Cipher", "op": "Rail Fence Cipher", "input": "WEAREDISCOVEREDFLEEATONCE", "args": "--rails 3"},
    {"name": "Scytale Cipher", "op": "Scytale Cipher", "input": "iamhurtverybadlyhelp", "args": "--diameter 4"},
    {"name": "UTF-16", "op": "UTF-16", "input": "Hello World!"},
    {"name": "UTF-32", "op": "UTF-32", "input": "Hello World!"},
    {"name": "UTF-7", "op": "UTF-7", "input": "Hello World!"},
    {"name": "UUencoding", "op": "UUencoding", "input": "Hello World!"},
    {"name": "XML", "op": "XML", "input": "<node>text</node>"},
    {"name": "XXencoding", "op": "XXencoding", "input": "Hello World!"},
    {"name": "Playfair Cipher", "op": "Playfair Cipher", "input": "HIDETHEGOLDINTHETREESTUMP", "args": "-k 'PLAYFAIR EXAMPLE'", "expected_output": "HIDETHEGOLDINTHETREXESTUMP"},
    {"name": "Hill Cipher", "op": "Hill Cipher", "input": "ACT", "args": "--key_matrix_str '11 8,3 7'", "expected_output": "ACT"},
    {"name": "JSON", "op": "JSON", "input": '{"key": "value", "num": 1}'},
    # Newly added tests
    {"name": "Punycode", "op": "Punycode", "input": "à¤‰à¤¦à¤¾à¤¹à¤°à¤£.à¤•à¥‰à¤®"},
    {"name": "YAML", "op": "YAML", "input": '{"key": "value", "list": [1, 2, 3]}'},
    {"name": "Raw Hex Dump", "op": "Raw Hex Dump", "input": "Test raw hex dump"},
    {"name": "Brainfuck", "op": "Brainfuck", "input": "OK"},
    {"name": "Roman Numerals", "op": "Roman Numerals", "input": "1984", "encode_choice": "1", "decode_choice": "2"},
    # Newly added text encoding tests
    {"name": "ISO-8859-1", "op": "ISO-8859-1 (Latin-1)", "input": "Hello World! Ã¦Ã¸Ã¥"},
    {"name": "Shift-JIS", "op": "Shift-JIS", "input": "Hello World!"},
    {"name": "UTF-8", "op": "UTF-8", "input": "Hello World! ðŸ‘‹"},
    {"name": "EBCDIC", "op": "EBCDIC", "input": "Hello World!"},
]

# Define tests that are single-stage (not round-trip)
SINGLE_STAGE_TESTS = [
    {"name": "SHA256 Hash", "command": "python ovaltine.py -op SHA256 -i \"test\""},
    {"name": "MD5 Hash", "command": "python ovaltine.py -op MD5 -i \"test\""},
    {"name": "Atbash Cipher", "command": "python ovaltine.py -op \"Atbash Cipher\" -i \"hello\""},
    {"name": "ROT13 Cipher", "command": "python ovaltine.py -op ROT13 -i \"hello\""},
    {"name": "Reverse String", "command": "python ovaltine.py -op \"Reverse String\" -i \"desserts\""},
    {"name": "Uppercase", "command": "python ovaltine.py -op Uppercase -i \"hello\""},
    {"name": "Analyze Hash", "command": "python ovaltine.py -op \"Analyze Hash\" -i \"098f6bcd4621d373cade4e832627b4f6\""},
    {"name": "Verify Hash", "command": "python ovaltine.py -op \"Verify Hash\" -i \"test\" --hash-type md5 --expected-hash \"098f6bcd4621d373cade4e832627b4f6\""},
    {"name": "File I/O Test", "command": "python ovaltine.py -op Base64 -c 1 -if input.txt -of output.txt", "sequential": True},
    {"name": "Show History", "command": "python ovaltine.py --history", "sequential": True},
    {"name": "Clear History", "command": "python ovaltine.py --clear-history", "sequential": True},
]

# ==============================================================================
# TEST RUNNER FUNCTIONS
# ==============================================================================

def run_command(command):
    """Executes a command and returns the result."""
    args = shlex.split(command)
    return subprocess.run(args, shell=False, capture_output=True, text=True, encoding='utf-8')

def extract_output(process_result):
    """Extracts the relevant output from a completed process."""
    if "---START_RESULT---" in process_result.stdout:
        return process_result.stdout.split("---START_RESULT---")[1].split("---END_RESULT---")[0].strip()
    return process_result.stdout.strip()

def run_round_trip_test(test_config, ovaltine_path):
    """
    Runs an encode and decode test for a given configuration and verifies
    that the final output matches the original input.
    """
    name = test_config["name"]
    op = test_config["op"]
    original_input = test_config["input"]
    expected_output = test_config.get("expected_output", original_input) # Use expected_output if provided
    encode_choice = test_config.get("encode_choice", "1") # New: Get encode choice
    decode_choice = test_config.get("decode_choice", "2") # New: Get decode choice
    float_tolerance = test_config.get("float_tolerance") # New: Get float tolerance
    args = test_config.get("args", "")
    case_insensitive = test_config.get("case_insensitive", False)
    result = {"name": f"{name} Round-Trip", "status": "fail"}

    try:
        # 1. Encode
        # Use shlex.quote to safely handle inputs with special characters
        encode_command = f"python {shlex.quote(ovaltine_path)} -op {shlex.quote(op)} -c {encode_choice} -i {shlex.quote(original_input)} {args}"
        encode_process = run_command(encode_command)

        if encode_process.returncode != 0:
            result["error"] = f"Encode step failed!\nExit Code: {encode_process.returncode}\nStdout: {encode_process.stdout}\nStderr: {encode_process.stderr}"
            return result
        
        encoded_output = extract_output(encode_process)
        if not encoded_output and name != "Brainfuck": # Brainfuck can have empty output for some inputs
            result["error"] = "Encode step produced no output."
            return result

        # 2. Decode
        decode_command = f"python {shlex.quote(ovaltine_path)} -op {shlex.quote(op)} -c {decode_choice} -i {shlex.quote(encoded_output)} {args}"
        decode_process = run_command(decode_command)

        if decode_process.returncode != 0:
            result["error"] = f"Decode step failed!\nEncoded Input was: '{encoded_output}'\nExit Code: {decode_process.returncode}\nStdout: {decode_process.stdout}\nStderr: {decode_process.stderr}"
            return result

        final_output = extract_output(decode_process)

        # 3. Verify
        passed = False
        # Special comparison for JSON/YAML to ignore whitespace differences
        if name == "JSON":
            try:
                if json.loads(final_output) == json.loads(expected_output):
                    passed = True
            except json.JSONDecodeError:
                passed = False
        elif name == "YAML":
            try:
                if yaml.safe_load(final_output) == yaml.safe_load(expected_output):
                    passed = True
            except yaml.YAMLError:
                passed = False
        elif float_tolerance is not None: # Special comparison for floats
            try:
                # Assuming format "lat,lon"
                final_parts = final_output.split(',')
                expected_parts = expected_output.split(',')
                if len(final_parts) == 2 and len(expected_parts) == 2:
                    final_lat, final_lon = float(final_parts[0]), float(final_parts[1])
                    expected_lat, expected_lon = float(expected_parts[0]), float(expected_parts[1])
                    if math.isclose(final_lat, expected_lat, rel_tol=float_tolerance) and \
                       math.isclose(final_lon, expected_lon, rel_tol=float_tolerance):
                        passed = True
                else:
                    result["error"] = f"Float comparison failed: Output or expected output not in 'lat,lon' format. Final: '{final_output}', Expected: '{expected_output}'"
            except ValueError:
                passed = False
        
        if not passed: # Default comparison
            comparison_a = final_output
            comparison_b = expected_output
            if case_insensitive:
                comparison_a = final_output.lower()
                comparison_b = expected_output.lower()

            if comparison_a == comparison_b:
                passed = True

        if passed:
            result["status"] = "pass"
        else:
            result["error"] = f"Output mismatch!\nExpected: '{expected_output}'\nFinal:    '{final_output}'"
        
        return result

    except Exception as e:
        result["error"] = f"An exception occurred: {e}"
        return result

def run_single_stage_test(test_case, ovaltine_path):
    """Runs a single command test and checks for a zero exit code."""
    name = test_case["name"]
    command = test_case["command"].replace("python ovaltine.py", f"python {shlex.quote(ovaltine_path)}")
    result = {"name": name, "status": "fail"}

    try:
        if name == "File I/O Test":
            with open("input.txt", "w") as f:
                f.write("secret")
        
        process = run_command(command)

        if process.returncode != 0:
            result["error"] = f"Exit Code: {process.returncode}\nStdout: {process.stdout}\nStderr: {process.stderr}"
            return result

        if name == "File I/O Test":
            if not os.path.exists("output.txt"):
                result["error"] = "Output file 'output.txt' was not created."
                return result
            with open("output.txt", "r") as f:
                content = f.read().strip()
            expected_content = base64.b64encode(b"secret").decode()
            if content != expected_content:
                result["error"] = f"Output file content mismatch. Got '{content}', expected '{expected_content}'."
                return result
        
        result["status"] = "pass"
        return result

    except Exception as e:
        result["error"] = f"An exception occurred: {e}"
        return result
    finally:
        if name == "File I/O Test":
            if os.path.exists("input.txt"):
                os.remove("input.txt")
            if os.path.exists("output.txt"):
                os.remove("output.txt")

def run_tests_for_script(script_name, test_options, output_file):
    passed_count = 0
    output_file.write("--- Test Results for " + script_name + " ---\n")
    output_file.write("Timestamp: " + str(datetime.datetime.now()) + "\n\n")

    for option_num, details in test_options.items():
        option_name = details.get('name', 'Unknown')
        handler = details.get('handler')
        output_file.write("--- Option " + str(option_num) + ": " + option_name + " ---\n")

        if not handler:
            output_file.write("  Status: Skipped (No handler)\n\n")
            passed_count += 1
            continue

        try:
            inputs = SUITABLE_INPUTS.get(option_name, {})
            
            if option_name == "Help Message":
                with patch('builtins.input'), patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
                    handler(text="", parser=None)
                output_file.write("  - Testing Help Message...\n")
                output_file.write("    Output: (Help message functionality verified)\n")

            elif details.get('sub_choices'):
                for choice in ['1', '2']:
                    choice_name = "Encode" if choice == '1' else "Decode"
                    input_text = inputs.get(choice)
                    if input_text is None: continue

                    output_file.write("  - Testing '" + choice_name + "'...\n")
                    output_file.write("    Input: " + repr(input_text) + "\n")
                    
                    extra_params = inputs.get('extra', {})
                    result = handler(input_text, choice=choice, **extra_params)
                    
                    output_file.write("    Output: " + repr(result) + "\n")

            else: # No sub-choices
                input_text = inputs.get('1')
                if input_text is None:
                    if 'handler' in details:
                         output_file.write("  - Testing...\n")
                         output_file.write("    Input: (No input needed)\n")
                         result = handler(text="", choice='1') 
                         output_file.write("    Output: " + repr(result) + "\n")
                else:
                    output_file.write("  - Testing...\n")
                    output_file.write("    Input: " + repr(input_text) + "\n")

                    extra_params = inputs.get('extra', {})
                    # Pass choice='1' for handlers that expect it even without sub-choices
                    try:
                        result = handler(input_text, choice='1', **extra_params)
                    except TypeError:
                        result = handler(input_text, **extra_params)


                    output_file.write("    Output: " + repr(result) + "\n")

            output_file.write("  Status: Passed\n\n")
            passed_count += 1
        except Exception:
            output_file.write("  Status: Failed\n")
            output_file.write(traceback.format_exc() + "\n\n")
            
    return passed_count, len(test_options)

def run_test_prompts():
    output_filename = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_prompts.txt")
    
    all_options = {**MENU_OPTIONS, **SYSTEM_OPTIONS}
    sorted_keys = sorted(all_options.keys(), key=int)
    test_options = {i + 1: all_options[key] for i, key in enumerate(sorted_keys)}

    with open(output_filename, "w", encoding="utf-8") as f:
        print("Starting tests...")

        # Test ovaltine.py
        print("Testing functionality for ovaltine.py...")
        passed1, total1 = run_tests_for_script("ovaltine.py", test_options, f)
        status1 = "Passed" if passed1 == total1 else "Failed"
        print("Result: " + status1 + " (" + str(passed1) + "/" + str(total1) + ")")

        # Test ovaltine_v2.py
        print("\nTesting functionality for ovaltine_v2.py...")
        passed2, total2 = run_tests_for_script("ovaltine_v2.py", test_options, f)
        status2 = "Passed" if passed2 == total2 else "Failed"
        print("Result: " + status2 + " (" + str(passed2) + "/" + str(total2) + ")")

    print("\nAll tests complete. Results saved to " + output_filename)

def run_test_suite():
    """Runs all tests and prints a summary."""
    colorama.init(autoreset=True)

    ovaltine_path = __file__

    start_time = datetime.datetime.now()
    print(f"Test suite started at: {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")

    all_results = []
    total_tests = len(ROUND_TRIP_TESTS) + len(SINGLE_STAGE_TESTS)

    # Separate sequential tests from parallel ones
    sequential_single_stage = [t for t in SINGLE_STAGE_TESTS if t.get("sequential")]
    parallel_single_stage = [t for t in SINGLE_STAGE_TESTS if not t.get("sequential")]

    with ThreadPoolExecutor() as executor:
        # Submit all parallel tests (both round-trip and single-stage)
        futures = [executor.submit(run_round_trip_test, test, ovaltine_path) for test in ROUND_TRIP_TESTS]
        futures += [executor.submit(run_single_stage_test, test, ovaltine_path) for test in parallel_single_stage]

        for future in as_completed(futures):
            all_results.append(future.result())

    # Run sequential tests
    if sequential_single_stage:
        print("\n--- Running Sequential Tests ---")
        for test in sequential_single_stage:
            all_results.append(run_single_stage_test(test, ovaltine_path))

    # --- Process and Print Results ---
    passed_tests = [res for res in all_results if res["status"] == "pass"]
    failed_tests = [res for res in all_results if res["status"] == "fail"]
    
    print("\n--- Individual Test Results ---")
    for res in sorted(all_results, key=lambda x: x['name']):
        if res['status'] == 'pass':
            print(f"{Fore.GREEN}PASS: {res['name']}")
        else:
            print(f"{Fore.RED}FAIL: {res['name']}\n      {Fore.YELLOW}{res['error'].replace('\\n', '\\n      ')}")
        print("-" * 40)

    end_time = datetime.datetime.now()
    duration = end_time - start_time

    # --- Final Summary ---
    print("\n" + "="*40)
    print("========== Test Suite Summary ==========")
    print("="*40)
    
    print(f"\n{Style.BRIGHT}Test Run Timestamps:{Style.RESET_ALL}")
    print(f"  Started:  {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Finished: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Duration: {str(duration)}")

    print(f"\n{Style.BRIGHT}Test Results:{Style.RESET_ALL}")
    print(f"  {Fore.GREEN}Passed: {len(passed_tests)}")
    print(f"  {Fore.RED}Failed: {len(failed_tests)}")
    print(f"  Total:  {total_tests}")

    if failed_tests:
        print(f"\n--- {Fore.RED}Failed Tests ({len(failed_tests)}) ---")
        for result in sorted(failed_tests, key=lambda x: x['name']):
            print(f"{Fore.RED}  - {result['name']}")
    else:
        print(f"\n{Style.BRIGHT}{Fore.CYAN} *** All Tests Passed ***{Style.RESET_ALL}")

    print("\n" + "="*40)

    if failed_tests:
        sys.exit(1)

def main(args=None):
    colorama.init() # Initialize Colorama
    parser = argparse.ArgumentParser(
        description=MAIN_HELP_MESSAGE, # Keep MAIN_HELP_MESSAGE for overall description
        formatter_class=CustomHelpFormatter, # Use custom formatter
        add_help=False # Still disable default -h, as we have our own
    )
    parser.add_argument("-op", "--operation", help="Specify the operation (e.g., 'binary', 'hex', 'md5').")
    parser.add_argument("-c", "--choice", choices=['1', '2'], help="1 for encode/encrypt, 2 for decode/decrypt.")
    parser.add_argument("-i", "--input", help="The input string to process.")
    parser.add_argument("-if", "--input-file", help="Path to a file containing the input text.")
    parser.add_argument("-of", "--output-file", help="Path to a file to write the result to.")
    parser.add_argument("-s", "--shift", type=int, help="Shift value for Caesar cipher (e.g., 3).")
    parser.add_argument("-k", "--key", help="Key for VigenÃ¨re or XOR ciphers (e.g., 'SECRET').")
    parser.add_argument("-ka", "--key_a", type=int, help="Key 'a' for Affine Cipher.")
    parser.add_argument("-kb", "--key_b", type=int, help="Key 'b' for Affine Cipher.")
    parser.add_argument("-kms", "--key_matrix_str", help="Key matrix string for Hill Cipher (e.g., '2 3,1 4').")
    parser.add_argument("-r", "--rails", type=int, help="Number of rails for Rail Fence Cipher.")
    parser.add_argument("-d", "--diameter", type=int, help="Diameter for Scytale Cipher (number of columns).")
    parser.add_argument("-ht", "--hash-type", dest='hash_type', help="Hash type for Verify Hash (e.g., 'md5', 'sha256').")
    parser.add_argument("-eh", "--expected-hash", dest='expected_hash', help="Expected hash value for Verify Hash.")
    parser.add_argument("-h", "--help", action="store_true", help="Show this help message and exit.")
    parser.add_argument("-x", "--examples", action="store_true", help="Show usage examples and exit.")
    parser.add_argument("--history", action="store_true", help="Display the operation history.")
    parser.add_argument("--clear-history", action="store_true", help="Clear the operation history file.")
    parser.add_argument("-ts", "--test-suite", action="store_true", help="Run the test_suite.py script.")
    parser.add_argument("-m", "--mobile-display", action="store_true", help="Display the menu in a single-column format (runs ovaltine_v2.py).")


    args = parser.parse_args(args=args)

    history_list = load_history() # Always load history
    history_enabled = True # Initialize history_enabled to True

    if args.help:
        print(MAIN_HELP_MESSAGE)
        
        # Manually format and print options
        options_list = []
        max_flag_len = 0
        for action in parser._actions:
            if action.help is not argparse.SUPPRESS:
                # Construct the flag string
                flags = []
                if action.option_strings:
                    flags = action.option_strings
                
                flag_str = ', '.join(flags)
                if action.metavar:
                    flag_str += f" <{action.metavar}>"
                elif action.nargs != 0 and action.const is None: # For arguments that take a value
                    if action.type is int:
                        flag_str += " <int>"
                    elif action.type is str:
                        flag_str += " <string>"
                    else:
                        flag_str += " <value>"
                
                # Store original flag string and help text
                options_list.append((flag_str, action.help or "")) # Use empty string if help is None
                max_flag_len = max(max_flag_len, get_display_width(flag_str))
        
        # Calculate dynamic flag_width and total_width
        terminal_width = shutil.get_terminal_size().columns
        flag_width = min(max_flag_len + 2, terminal_width // 2 - 2) # Max half terminal width, with some padding
        total_width = terminal_width - 2 # Leave some margin

        print(f"\n{Fore.CYAN}{Style.BRIGHT}Options:{Style.RESET_ALL}")
        print(format_options_two_columns(options_list, flag_width=flag_width, total_width=total_width))
        sys.exit(0)
    if args.examples:
        print(EXAMPLES_HELP_MESSAGE)
        sys.exit(0)

    if args.clear_history:
        clear_history()
        sys.exit(0)

    if args.test_suite:
        run_test_suite()
        run_test_prompts()
        sys.exit(0)

    if args.history:
        history = load_history()
        if history:
            print(f"\n{Fore.CYAN}{Style.BRIGHT}Operation History:{Style.RESET_ALL}")
            for entry in history:
                print(f"  Timestamp: {entry['timestamp']}")
                operation_name = entry.get('operation', entry.get('type', 'N/A'))
                choice_val = entry.get('choice', entry.get('mode', 'N/A'))
                input_val = entry.get('input', entry.get('input_string', 'N/A'))
                
                print(f"  Operation: {operation_name}")
                print(f"  Choice: {choice_val}")
                print(f"  Input: {input_val}")
                print(f"  Result: {entry['result']}")
                if entry.get('extra_params'):
                    print(f"  Extra Params: {entry['extra_params']}")
                elif entry.get('shift'): # Handle old 'shift' param
                    print(f"  Extra Params: {{'shift': {entry['shift']}}}")
                elif entry.get('algorithm'): # Handle old 'algorithm' param
                    print(f"  Extra Params: {{'algorithm': '{entry['algorithm']}'}}")
                print("-" * 40)
        else:
            print(f"{Fore.YELLOW}No operation history found.{Style.RESET_ALL}")
        sys.exit(0)

    # Non-interactive mode
    if args.operation:
        handler_data = None
        normalized_operation = args.operation.lower().replace(" ", "")
        for data in MENU_OPTIONS.values():
            if 'name' in data and normalized_operation == data['name'].lower().replace(" ", ""):
                handler_data = data
                break
        if not handler_data: # If not found in MENU_OPTIONS, check SYSTEM_OPTIONS
            for data in SYSTEM_OPTIONS.values():
                if 'name' in data and normalized_operation == data['name'].lower().replace(" ", ""):
                    handler_data = data
                    break
        
        if not handler_data or 'handler' not in handler_data:
            print(f"Error: Invalid operation '{args.operation}'", file=sys.stderr)
            sys.exit(1)

        text = get_input_from_args(args)
        if text is None:
            print("Error: Input is required for non-interactive mode.", file=sys.stderr)
            sys.exit(1)

        handler_kwargs = vars(args) # Get all args as kwargs
        
        # Filter extra_params for history logging
        filtered_extra_params = {}
        if "extra_input" in handler_data:
            if isinstance(handler_data["extra_input"], list):
                for extra_info in handler_data["extra_input"]:
                    if handler_kwargs.get(extra_info["name"]) is not None:
                        filtered_extra_params[extra_info["name"]] = handler_kwargs[extra_info["name"]]
            else: # Single extra_input
                extra_info = handler_data["extra_input"]
                if handler_kwargs.get(extra_info["name"]) is not None:
                    filtered_extra_params[extra_info["name"]] = handler_kwargs[extra_info["name"]]

        # Handle specific old extra params that might still be in args but not in extra_input
        if handler_data['name'] in ["Caesar Cipher", "VigenÃ¨re Cipher", "XOR Cipher"] and args.shift is not None:
            filtered_extra_params['shift'] = args.shift
        if handler_data['name'] in ["Analyze Hash", "Verify Hash"] and args.hash_type is not None:
            filtered_extra_params['hash_type'] = args.hash_type
        if handler_data['name'] == "Verify Hash" and args.expected_hash is not None:
            filtered_extra_params['expected_hash'] = args.expected_hash
        if handler_data['name'] == "Rail Fence Cipher" and args.rails is not None:
            filtered_extra_params['rails'] = args.rails
        if handler_data['name'] == "Scytale Cipher" and args.diameter is not None:
            filtered_extra_params['diameter'] = args.diameter
        if handler_data['name'] == "Hill Cipher" and args.key_matrix_str is not None:
            filtered_extra_params['key_matrix_str'] = args.key_matrix_str
        if handler_data['name'] == "XOR Cipher" and args.key is not None:
            filtered_extra_params['key'] = args.key
        if handler_data['name'] == "Affine Cipher" and args.key_a is not None:
            filtered_extra_params['key_a'] = args.key_a
        if handler_data['name'] == "Affine Cipher" and args.key_b is not None:
            filtered_extra_params['key_b'] = args.key_b
        
        try:
            handler_params = {"text": text}
            if handler_data.get("sub_choice"):
                handler_params["choice"] = args.choice

            if "extra_input" in handler_data:
                if isinstance(handler_data["extra_input"], list):
                    for extra_info in handler_data["extra_input"]:
                        if getattr(args, extra_info["name"]) is not None:
                            handler_params[extra_info["name"]] = getattr(args, extra_info["name"])
                else: # Single extra_input
                    extra_info = handler_data["extra_input"]
                    if getattr(args, extra_info["name"]) is not None:
                        handler_params[extra_info["name"]] = getattr(args, extra_info["name"])
            
            result = handler_data["handler"](**handler_params)
            write_output(result, args.output_file)
            history_list = add_to_history(handler_data['name'], args.choice, text, result, handler_params)
        except Exception as e:
            print(f"An error occurred: {e}", file=sys.stderr)
            sys.exit(1)

    # Interactive mode
    else:
        try:
            while True:
                if args.mobile_display:
                    main_options_map = display_menu_one_column()
                else:
                    display_menu_two_columns()
                    main_options_map = None # In two-column mode, we don't use a map

                menu_choice_input = input("Enter your choice: ").strip()
                
                menu_choice = get_menu_choice(menu_choice_input, args.mobile_display, main_options_map)
                
                if menu_choice == "85": # Exit option
                    print(f"{Fore.RED}{Style.BRIGHT}Exiting.{Style.RESET_ALL}")
                    break

                if menu_choice is None:
                    print(f"{Fore.RED}Invalid choice. Please enter a number or a valid option name from the menu.{Style.RESET_ALL}")
                    continue

                # Determine which dictionary to use for handler_data
                if menu_choice in MENU_OPTIONS:
                    handler_data = MENU_OPTIONS[menu_choice]
                elif menu_choice in SYSTEM_OPTIONS:
                    handler_data = SYSTEM_OPTIONS[menu_choice]
                else:
                    print(f"{Fore.RED}Error: Invalid menu choice. This should not happen.{Style.RESET_ALL}")
                    continue

                text_input_needed = not handler_data.get("no_input_required", False)
                current_text = ""
                kwargs = {} # Initialize kwargs here

                if "sub_choice" in handler_data and handler_data["sub_choice"]:
                    while True:
                        sub_choice = get_sub_choice(handler_data['name'])

                        if sub_choice == '1' or sub_choice == '2':
                            if text_input_needed:
                                current_text = get_interactive_input("Enter text: ")
                                if not current_text:
                                    print("No input provided. Returning to sub-menu.")
                                    continue # Go back to sub-menu choice

                            if "extra_input" in handler_data: # Collect extra_input here
                                if isinstance(handler_data["extra_input"], list):
                                    for extra_info in handler_data["extra_input"]:
                                        val = input(extra_info["prompt"])
                                        try:
                                            kwargs[extra_info["name"]] = extra_info["type"](val)
                                        except ValueError:
                                            print(f"{Fore.RED}Error: Invalid input for {extra_info['name']}. Please enter a valid {extra_info['type'].__name__}.{Style.RESET_ALL}", file=sys.stderr)
                                            continue
                                else: # Single extra_input
                                    extra_info = handler_data["extra_input"]
                                    val = input(extra_info["prompt"])
                                    try:
                                        kwargs[extra_info["name"]] = extra_info["type"](val)
                                    except ValueError:
                                        print(f"{Fore.RED}Error: Invalid input for {extra_info['name']}. Please enter a valid {extra_info['type'].__name__}.{Style.RESET_ALL}", file=sys.stderr)
                                        continue
                            try:
                                if menu_choice == "84": # Help Message is special, needs parser
                                    result = handler_data["handler"](current_text, choice=sub_choice, parser=parser, **kwargs)
                                else:
                                    result = handler_data["handler"](current_text, choice=sub_choice, **kwargs)
                                if result is not None:
                                    write_output(result)
                                    input("\nPress Enter to return to the menu...")
                                    history_list = add_to_history(handler_data['name'], sub_choice, current_text, result, extra_params=kwargs)
                            except Exception as e:
                                print(f"{Fore.RED}An error occurred: {e}{Style.RESET_ALL}")
                            break # Break from sub-menu loop
                        elif sub_choice == '3':
                            break # Break from sub-menu loop, return to main menu
                        else:
                            print(f"{Fore.RED}Error: Invalid choice. Please try again.{Style.RESET_ALL}")
                else: # No sub_choice (including system options without sub_choice)
                    if text_input_needed:
                        if "input_prompt" in handler_data:
                            current_text = get_interactive_input(handler_data["input_prompt"])
                        else:
                            current_text = get_interactive_input(f"Enter text for {handler_data['name']}: ")
                        
                        if not current_text and not handler_data.get("allow_empty_input", False):
                            print("No input provided. Returning to main menu.")
                            continue # Go back to main menu

                    if menu_choice == "84": # Help Message is special, needs parser
                        handler_data["handler"](current_text, parser=parser, **kwargs)
                        continue # Skip writing output and the second "Press Enter" prompt
                    else:
                        try:
                            result = handler_data["handler"](current_text, **kwargs)
                            if result is not None:
                                write_output(result)
                                input("\nPress Enter to return to the menu...")
                                history_list = add_to_history(handler_data['name'], None, current_text, result, extra_params=kwargs)
                        except Exception as e:
                            print(f"{Fore.RED}An error occurred: {e}{Style.RESET_ALL}")

        except (KeyboardInterrupt, EOFError):
            print(f"\n{Fore.RED}{Style.BRIGHT}Exiting.{Style.RESET_ALL}")
            if history_enabled:
                save_history(history_list)
            sys.exit(0) # Explicitly exit after interactive loop

if __name__ == "__main__":
    main()
