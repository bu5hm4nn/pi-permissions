---
name: heredoc-classifier
description: Classify heredoc scripts as readonly (safe), modify (writes/deletes), or unknown. Use when analyzing shell commands containing heredocs to determine approval tier.
---

# Heredoc Classifier

Classify heredoc script content by its risk level: readonly, modify, or unknown.

## Input

You will receive a heredoc script with its detected language. Analyze its behavior.

## Classification Rules

### READONLY (auto-approve tier)
Scripts that ONLY:
- Read files (`open(f, 'r')`, `cat`, `head`, `less`)
- Print/output (`print()`, `echo`, `console.log`)
- Compute/transform in memory
- Make GET requests (curl GET, requests.get)
- Query databases (SELECT only)
- List/enumerate (`ls`, `find`, `grep`)

### MODIFY (require approval)
Scripts that:
- Write files (`open(f, 'w')`, `open(f, 'a')`, `>`, `>>`)
- Delete files (`os.remove`, `rm`, `unlink`, `shutil.rmtree`)
- Create directories (`mkdir`, `os.makedirs`)
- Modify files (`sed -i`, in-place edits)
- Execute system commands with write effects
- Make POST/PUT/DELETE/PATCH requests
- Modify databases (INSERT, UPDATE, DELETE, DROP)
- Run subprocesses that write

### UNKNOWN
- Cannot determine behavior confidently
- Uses dynamic constructs that obscure intent
- External dependencies with unknown behavior

## Language-Specific Patterns

### Python
```
READONLY:  open(f, 'r'), print(), requests.get(), json.load()
MODIFY:    open(f, 'w'), open(f, 'a'), os.remove(), shutil.rmtree(), 
           subprocess.run([...rm...]), requests.post/put/delete()
```

### Bash
```
READONLY:  cat, head, tail, grep, find, ls, read, echo (to stdout)
MODIFY:    >, >>, rm, mv, cp, mkdir, touch, chmod, chown, sed -i
```

### JavaScript/Node
```
READONLY:  fs.readFile, fs.readdir, console.log, fetch (GET)
MODIFY:    fs.writeFile, fs.appendFile, fs.unlink, fs.mkdir, 
           child_process.spawn with writes
```

### Ruby
```
READONLY:  File.read, puts, p, File.open(f, 'r')
MODIFY:    File.write, File.open(f, 'w'), FileUtils.rm, FileUtils.mkdir
```

### Perl
```
READONLY:  open(F, "<$f"), print, say
MODIFY:    open(F, ">$f"), open(F, ">>$f"), unlink, mkdir
```

## Output Format

Return JSON:
```json
{
  "classification": "readonly" | "modify" | "unknown",
  "language": "python" | "bash" | "javascript" | "ruby" | "perl" | "unknown",
  "confidence": "high" | "medium" | "low",
  "reasoning": "Brief explanation of detected patterns",
  "write_operations": ["list of write operations found, if any"]
}
```

## Examples

### Example 1: Python Readonly
```python
python3 - <<'PY'
import requests
from bs4 import BeautifulSoup
url = 'https://example.com'
resp = requests.get(url)
soup = BeautifulSoup(resp.text, 'html.parser')
print(soup.find('title').text)
PY
```
**Answer:**
```json
{
  "classification": "readonly",
  "language": "python",
  "confidence": "high",
  "reasoning": "Only reads URL with GET request, parses HTML, prints output",
  "write_operations": []
}
```

### Example 2: Python Modify
```python
python3 - <<'PY'
import os
import shutil
shutil.rmtree('./build')
os.makedirs('./dist')
with open('output.txt', 'w') as f:
    f.write('data')
PY
```
**Answer:**
```json
{
  "classification": "modify",
  "language": "python",
  "confidence": "high",
  "reasoning": "Deletes directory (rmtree), creates directory (makedirs), writes file",
  "write_operations": ["shutil.rmtree", "os.makedirs", "open(..., 'w')"]
}
```

### Example 3: Bash Modify
```bash
bash <<'SCRIPT'
find . -name "*.log" -exec rm {} \;
cat input.txt | sed 's/old/new/' > output.txt
SCRIPT
```
**Answer:**
```json
{
  "classification": "modify",
  "language": "bash",
  "confidence": "high",
  "reasoning": "Deletes files (rm), writes to file (>)",
  "write_operations": ["rm", ">"]
}
```

### Example 4: Unknown
```python
python3 - <<'PY'
import sys
module = sys.argv[1]
__import__(module).run()
PY
```
**Answer:**
```json
{
  "classification": "unknown",
  "language": "python",
  "confidence": "low",
  "reasoning": "Dynamically imports and executes module by name, behavior depends on runtime input",
  "write_operations": []
}
```

## Instructions

1. Analyze the heredoc content
2. Detect the programming language
3. Identify read vs write operations
4. Classify as readonly/modify/unknown
5. Return JSON with your reasoning

Be thorough but fast. This classification drives approval tiers for SSH command execution.