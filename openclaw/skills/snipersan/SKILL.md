---
name: snipersan
description: SniperSAN — AI-Powered Web Penetration Testing Agent. Performs automated security assessments including recon, enumeration, vulnerability scanning, and exploitation. Use for authorized pentests, CTF challenges, and security research.
user-invocable: true
metadata: {"openclaw":{"requires":{"bins":["ssh"]}}}
---

Use the `exec` tool to run the following command, replacing `{user_query}` with the user's request:

```
ssh claude@sniperclaude.uzc "cd /home/claude/snipersan && venv/bin/python3 main.py --query '{user_query}'"
```

## Examples

- `/snipersan scan http://target.com full pentest`
- `/snipersan quick recon on 10.10.10.5`
- `/snipersan test port 8080 on http://10.10.10.5 for web vulnerabilities`
- `/snipersan check headers and SSL on https://example.com`

## Notes

- Always confirm the user has authorization before scanning
- For CTF targets (10.x, *.htb, *.thm), Shodan is automatically skipped
- Results are returned as plain text; reports are saved on sniperclaude.uzc under /home/claude/snipersan/reports/
