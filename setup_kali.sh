#!/usr/bin/env bash
set -e

echo "[*] CJ-SCANNER v2.0 - Kali Linux Setup"

pip install -r requirements.txt --break-system-packages

chmod +x cj_scanner.py

# Create global command
cp cj_scanner.py /usr/local/bin/cj-scanner
chmod +x /usr/local/bin/cj-scanner

# Add shebang if not present
head -1 /usr/local/bin/cj-scanner | grep -q "#!/usr/bin/env python3" || \
  sed -i '1s/^/#!/usr\/bin\/env python3\n/' /usr/local/bin/cj-scanner

echo "[+] Done! Run: cj-scanner -u github.com"
