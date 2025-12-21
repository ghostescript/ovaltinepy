# ovaltinepy
Encoder • Decoder • Hasher

## Project Description
``ovaltinepy`` is a powerful and versatile command-line tool designed for a wide range of encoding, decoding, hashing, and string manipulation tasks. Whether you're a security professional, a developer, or just someone who needs to quickly transform data, Ovaltine provides a comprehensive suite of functionalities accessible via an interactive menu or direct command-line arguments.

## Features
-   **Extensive Encoding/Decoding:** Support for common formats like Base64, Hexadecimal, URL, HTML Entities, ASCII, Punycode, XML, JSON, YAML, and various UTF encodings.
-   **Classic Ciphers:** Implementations of ROT13, Caesar, Atbash, Vigenère, XOR, Morse Code, A1Z26, Baconian, Polybius Square, Affine, Playfair, Hill, Rail Fence, and Scytale ciphers.
-   **Hashing Algorithms:** Generate MD5, SHA-1, SHA256, SHA512, CRC32, Adler-32, SHA3, BLAKE2b, and BLAKE2s hashes. Includes hash analysis and verification.
-   **String Manipulation:** Functions for reversing, changing case (uppercase, lowercase, capitalize, title case, swap case), and Leet (1337) speak.
-   **Numeric System Conversions:** Convert between Decimal, Hex, Octal, IP Address to Integer, Integer to IP Address, Roman Numerals, Binary Coded Decimal (BCD), Base36, and Base62.
-   **Miscellaneous Tools:** Quoted-Printable, UUencoding, XXencoding, Hexlify, EBCDIC, Luhn Algorithm, Geohash, UUID generation/parsing, Raw Hex Dump, Brainfuck, and Tap Code.
-   **Compression/Decompression:** Zlib, Gzip, Bzip2, LZMA, Deflate, and Zstandard compression (input/output handled as Base64).
-   **Interactive Menu:** User-friendly interactive mode for easy navigation and operation selection.
-   **Command-Line Interface (CLI):** Execute operations directly from the command line for scripting and automation.
-   **Operation History:** Keep track of your past operations.
-   **Mobile-Friendly Display:** A dedicated single-column menu display for smaller terminals.

## Installation

### Prerequisites
-   Python 3.x
-   `pip` (Python package installer)

### From PyPI (Recommended)
*[ovaltinepy 0.1.7](https://pypi.org/project/ovaltinepy)*
```bash
pip install ovaltinepy
```
*or optionally without venv*
```bash
pip install ovaltinepy --break-system-packages
```

### From Source
1.  Clone the Repository:
    ```bash
    git clone https://github.com/ghostescript/ovaltinepy
    cd ovaltinepy
    ```
2.  Virtual Environment:
    ```bash
    python -m venv .venv
    source .venv/bin/activate
    ```
3.  Install Dependencies:
    ```bash
    pip install -r requirements.txt
    ```
4.  Make Executable:
    ```bash
    chmod +x ovaltine.py
    ```

### Quick Install
*Linux*
```bash
git clone https://github.com/ghostescript/ovaltinepy
cd ovaltinepy
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
chmod +x ovaltine.py
python ovaltine.py
```
*Termux*
```bash
git clone https://github.com/ghostescript/ovaltinepy
cd ovaltinepy
pip install -r requirements.txt
chmod +x ovaltine.py
python ovaltine.py
```

## Usage

### Interactive Mode
Run the script without any arguments to enter interactive mode:
```bash
python ovaltine.py
```
A menu will be displayed, allowing you to choose from various operations. Follow the prompts to input text, select encode/decode options, and provide any necessary extra parameters (like shift values or keys).

### Command-Line Mode
You can perform operations directly from the command line using arguments.

**General Usage:**
```
┌──(kali㉿localhost)-[~/ovaltinepy]
└─$ python ovaltine.py -h

Encoder/Decoder/Hasher Tool Help

This versatile command-line tool provides a wide range of encoding, decoding, hashing,
and string manipulation functionalities. It can be used interactively or via
command-line arguments for automation.

Interactive Mode:
Run the script without any arguments to enter interactive mode. A menu will be
displayed, allowing you to choose from various operations. Follow the prompts
to input text, select encode/decode options, and provide any necessary extra
parameters (like shift values or keys).

Command-Line Mode:
You can perform operations directly from the command line using arguments.

Usage:
  python ovaltine.py [OPTIONS]

Notes:
  - Operation names are case-insensitive and spaces are ignored when matching.
  - For operations requiring extra input (like 'shift' or 'key'), provide them
    as additional command-line arguments.
  - Some operations (e.g., 'Analyze Hash', 'Auto Detect') do not require a
    'choice' argument.


Options:
  -op, --operation <value>         Specify the operation (e.g., 'binary', 'hex', 'md5').
  -c, --choice <value>             1 for encode/encrypt, 2 for decode/decrypt.
  -i, --input <value>              The input string to process.
  -if, --input-file <value>        Path to a file containing the input text.
  -of, --output-file <value>       Path to a file to write the result to.
  -s, --shift <int>                Shift value for Caesar cipher (e.g., 3).
  -k, --key <value>                Key for Vigenère or XOR ciphers (e.g., 'SECRET').
  -ka, --key_a <int>               Key 'a' for Affine Cipher.
  -kb, --key_b <int>               Key 'b' for Affine Cipher.
  -kms, --key_matrix_str <value>   Key matrix string for Hill Cipher (e.g., '2 3,1 4').
  -r, --rails <int>                Number of rails for Rail Fence Cipher.
  -d, --diameter <int>             Diameter for Scytale Cipher (number of columns).
  -ht, --hash_type <value>         Hash type for verification (e.g., 'md5', 'sha256').
  -eh, --expected_hash <value>     Expected hash value for verification.
  -h, --help                       Show this help message and exit.
  -x, --examples                   Show usage examples and exit.
  --history                        Display the operation history.
  --clear-history                  Clear the operation history file.
  -ts, --test-suite                Run the test_suite.py script.
  -m, --mobile-display             Display the menu in a single-column format (runs ovaltine_v2.py).
```

## Supported Operations (Detailed)

### Common Encodings
-   Binary, Hexadecimal, Base64, URL (Percent) Encoding, HTML Entities, ASCII Values, Punycode, XML, JSON, YAML, ISO-8859-1 (Latin-1), Shift-JIS, UTF-7, UTF-8, UTF-16, UTF-32, Base32, Base58, Base85, Base91.

### Classic Ciphers
-   ROT13, Caesar Cipher, Atbash Cipher, Morse Code, A1Z26 Cipher, Vigenère Cipher, Baconian Cipher, Polybius Square, Affine Cipher, Playfair Cipher, Hill Cipher, Rail Fence Cipher, Scytale Cipher, XOR Cipher.

### String Manipulation
-   Reverse String, Uppercase, Lowercase, Capitalize, Title Case, Swap Case, Leet (1337).

### Hashing (One-Way)
-   Analyze Hash, Verify Hash, MD5, SHA-1, SHA256, SHA512, CRC32, Adler-32, SHA3-224, SHA3-256, SHA3-384, SHA3-512, BLAKE2b, BLAKE2s.

### Numeric Systems
-   Decimal to Hex, Hex to Decimal, Decimal to Octal, Octal to Decimal, IP Address to Integer, Integer to IP Address, Roman Numerals, Binary Coded Decimal (BCD), Base36, Base62.

### Miscellaneous
-   Quoted-Printable, UUencoding, XXencoding, Hexlify, EBCDIC, Luhn Algorithm, Geohash, UUID (Generate/Parse), Raw Hex Dump, Brainfuck, Tap Code.

### Compression
-   Zlib Compress, Gzip Compress, Bzip2 Compress, LZMA Compress, Deflate, Zstandard Compress.

## Mobile-Friendly Display
A dedicated single-column menu display for smaller terminals.
```bash
python ovaltine.py -m
```

## Testing
To run the full test suite, including both functional tests and prompt verification tests:
```bash
python ovaltine.py --test-suite
```

## Contributing
Contributions are welcome! Please feel free to submit issues, pull requests, or suggest new features.

<br>

## Updated On
*``Dec 21, 2025``*

<br>
