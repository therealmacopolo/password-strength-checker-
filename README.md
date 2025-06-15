
 Password Strength Analyzer CLI

A powerful, terminal-based **Password Strength Analyzer** written in Python.  
It checks your password for:
- Length and character diversity
- Common password usage
- Repetitive and predictable patterns
- Password entropy
- Exposure in real-world data breaches (via Have I Been Pwned)

 Features

✅ Password strength scoring (up to 65 points)  
✅ Entropy estimation (bits of security)  
✅ Pattern detection (keyboard, repeated, sequential)  
✅ Breach detection using [Have I Been Pwned API](https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange)  
✅ CLI options for automation and interactive use  
✅ JSON logging of results  
✅ Dockerized for safe, portable execution

 Installation

 Option 1: Run Locally

 1. Clone this repo
bash
git clone https://github.com/YOUR_USERNAME/password-strength-analyzer.git
cd password-strength-analyzer

2. Install requirements

```bash
pip install -r requirements.txt
```

#### 3. Run the analyzer

```bash
python password_strength_checker.py --interactive --check-breach --save-results
```

---

 Option 2: Run with Docker

 Build Docker image

```bash
docker build -t password-checker .
```

 2. Run interactively

```bash
docker run -it password-checker --interactive --check-breach --save-results
```

3. Mount current folder to save logs

```bash
docker run -it -v $(pwd):/app password-checker --interactive --check-breach --save-results
```

---

 Command Line Options

| Flag                   | Description                                    |
| ---------------------- | ---------------------------------------------- |
| `--password`, `-p`     | Analyze a password passed directly (insecure!) |
| `--interactive`, `-i`  | Secure password prompt (recommended)           |
| `--check-breach`, `-b` | Checks password against known breaches         |
| `--save-results`, `-s` | Saves analysis in `password_analysis_log.json` |

---

 Output Example

```
============================================================
           PASSWORD STRENGTH ANALYSIS REPORT
============================================================

 OVERALL STRENGTH: Strong
 SCORE: 50/65
 ENTROPY: 61.78 bits
 LENGTH: 13 characters

 BREACH CHECK:
   ✓ Not found in known data breaches

 DETAILED ANALYSIS:
   Length:
      ✓ Excellent length (12+ characters)
   Character Variety:
      ✓ Contains lowercase letters
      ✓ Contains uppercase letters
      ✓ Contains numbers
      ✓ Contains special characters
   Common Passwords:
      ✓ Not in common password list
   Patterns:
      ✓ No obvious patterns detected

 RECOMMENDATIONS:
   • Use a password manager to generate and store strong passwords
```

---

 Example Test Passwords

| Password       | Score | Strength    |
| -------------- | ----- | ----------- |
| `123456`       | 0     | Very Weak   |
| `Admin@2023`   | 35    | Strong      |
| `!Tr0ub4dor&3` | 55    | Very Strong |

---

 Output Logs

Results are saved in:

```bash
password_analysis_log.json
```

Each entry includes:

* Timestamp
* Score
* Entropy
* Detailed feedback
* (No password or hashes stored)

---

 Future Ideas

* Add GUI (Tkinter or web-based)
* Integrate with password manager API
* Add dark web exposure scan
* Use ML to detect human-generated vs. system-generated passwords

---

 Credits

* [HaveIBeenPwned API](https://haveibeenpwned.com/API/v3)
* Built by [Syrus Wahome](https://github.com/YOUR_USERNAME)

---

 License

MIT License — feel free to use, fork, or contribute!

```

