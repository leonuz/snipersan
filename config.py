import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).parent
REPORTS_DIR = BASE_DIR / "reports"
WORDLISTS_DIR = BASE_DIR / "wordlists"
TEMPLATES_DIR = BASE_DIR / "templates"

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
WPSCAN_API_TOKEN = os.getenv("WPSCAN_API_TOKEN", "")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
CLAUDE_MODEL = "claude-sonnet-4-6"

DEFAULT_TIMEOUT = 10
DEFAULT_THREADS = 20
MAX_DIRS_TO_SCAN = 500

TOOL_PATHS = {
    "nmap": "nmap",
    "sqlmap": "sqlmap",
    "nikto": "nikto",
    "gobuster": "gobuster",
    "ffuf": "ffuf",
}
