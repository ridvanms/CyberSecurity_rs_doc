# Nmap

Nmap (Network Mapper) is a free and open-source utility for network discovery and security auditing.

## Basic Commands

- `nmap -sS <target>`: TCP SYN scan
- `nmap -sU <target>`: UDP scan
- `nmap -sV <target>`: Version detection
- `nmap -A <target>`: Aggressive scan (includes OS detection, version detection, script scanning, and traceroute)

---
*Content from Cheatsheets/nmap.md*
---

# Nmap Cheatsheet

Nmap (Network Mapper) is a powerful open-source tool for network exploration and security auditing.

## Basic Scans

*   **Scan a single target:**
    ```bash
    nmap [target]
    ```

*   **Scan multiple targets:**
    ```bash
    nmap [target1] [target2] ...
    ```

*   **Scan a range of hosts:**
    ```bash
    nmap [target-range]
    ```
    (e.g., `192.168.1.1-100`)

*   **Scan a subnet:**
    ```bash
    nmap [target/mask]
    ```
    (e.g., `192.168.1.0/24`)

*   **Scan targets from a file:**
    ```bash
    nmap -iL [list.txt]
    ```

## Scan Techniques

*   **TCP SYN Scan (default):**
    ```bash
    nmap -sS [target]
    ```

*   **TCP Connect Scan:**
    ```bash
    nmap -sT [target]
    ```

*   **UDP Scan:**
    ```bash
    nmap -sU [target]
    ```

*   **FIN, NULL, X-MAS Scans:**
    ```bash
    nmap -sF [target]
    nmap -sN [target]
    nmap -sX [target]
    ```

## Service and Version Detection

*   **Detect services and their versions:**
    ```bash
    nmap -sV [target]
    ```

## OS Detection

*   **Detect the operating system:**
    ```bash
    nmap -O [target]
    ```

## NSE (Nmap Scripting Engine)

*   **Run default scripts:**
    ```bash
    nmap -sC [target]
    ```
    or
    ```bash
    nmap --script=default [target]
    ```

*   **Run a specific script:**
    ```bash
    nmap --script=[script-name] [target]
    ```

*   **Run scripts from a category:**
    ```bash
    nmap --script=[category] [target]
    ```
    (e.g., `vuln`, `exploit`, `auth`)

## Output Formats

*   **Save output to a file:**
    ```bash
    nmap -oN [output.txt] [target]
    ```

*   **Save output in all formats:**
    ```bash
    nmap -oA [output] [target]
    ```
    (creates `output.nmap`, `output.gnmap`, `output.xml`)