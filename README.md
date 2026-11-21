# Checksums Part 2

A project for parsing TCP/IP packets and calculating checksums. Uses Wireshark packet captures as input.

Team members:
- Jonathan Schultz (jss5874@rit.edu)
- Jay Stebbins (jks1805@rit.edu)
- Caden Seaman (cjs6589@rit.edu)
- Ryan Leifer (rjl8327@rit.edu)

# Setup

Requires Python 3.11+. Install the dependencies in a virtual environment:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

# Usage

Provide CLI arguments to specify the input file (any Wireshark capture exported as K12 text file):
```bash
python main.py <path_to_input_txt_file>
```