# cryptography-network-security-exam

ETTCS801 Cryptography and Network Security – Integrated Situation (ULK Polytechnic Institute).

## Structure
```
src/secure_records.py        Encrypt / decrypt / hash / verify tool (AES-256-GCM + SHA-256)
tests/test_secure_records.py Automated unit tests (unittest)
data/sample_students.csv     Fictional sample records (no real data)
firewall/firewall_rules.sh   iptables rules for the lab records server
risk_assessment.md           Task 1: assets, vulnerabilities, ranking, controls
filter_tests.md              Task 3d: firewall test commands, expected and actual results
evidence/                    Program output and firewall screenshots/output
report/report.tex, report.pdf  LaTeX technical report
```

## Installation
Requires Python 3.9+.
```bash
git clone https://github.com/<your-username>/cryptography-network-security-exam.git
cd cryptography-network-security-exam
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Running the programme
The key lives **outside** the repository (`~/.secure_records/master.key`, or set `SECURE_RECORDS_KEY`).
```bash
python3 src/secure_records.py keygen                                   # once
python3 src/secure_records.py encrypt data/sample_students.csv data/sample_students.enc
python3 src/secure_records.py decrypt-verify data/sample_students.enc data/sample_students.dec data/sample_students.csv
python3 src/secure_records.py verify data/sample_students.csv          # UNCHANGED / MODIFIED
python3 src/secure_records.py hash data/sample_students.csv            # re-baseline after an approved change
```
Exit codes: `0` success, `1` handled error (missing file, bad key, invalid/tampered ciphertext, empty file), `2` integrity mismatch.

Try tampering: `echo x >> data/sample_students.csv && python3 src/secure_records.py verify data/sample_students.csv` → `MODIFIED`.

## Reproducing the tests
```bash
python3 -m unittest discover -s tests -v      # 5 automated tests
sudo ./firewall/firewall_rules.sh apply       # lab server only; set SERVER_IP, GUEST_NET, STAFF_NET, SERVICE_PORT first
# then run the three connection tests listed in filter_tests.md
```
Build the report: `cd report && pdflatex report.tex && pdflatex report.tex`

## Security notes
No keys, passwords or real records are committed (`.gitignore` excludes `*.key`, `*.enc`, `*.dec`, `manifest.json`). Firewall rules are for the authorised laboratory only.
