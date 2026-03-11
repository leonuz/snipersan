"""Multi-LLM backend abstraction for SniperSAN.

Supports:
  - Claude (Anthropic API) — native tool use
  - Ollama (local server)  — tool use via OpenAI-compatible /v1/chat/completions
"""

import json
import sys
import requests
from typing import Any

import anthropic
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich import box

from config import ANTHROPIC_API_KEY, CLAUDE_MODEL, OLLAMA_HOST, OLLAMA_MODEL

console = Console()


# ─── Tool format converters ───────────────────────────────────────────────────

def _anthropic_to_openai_tools(tools: list[dict]) -> list[dict]:
    """Convert Anthropic tool format → OpenAI function-calling format (used by Ollama)."""
    openai_tools = []
    for t in tools:
        openai_tools.append({
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t.get("description", ""),
                "parameters": t.get("input_schema", {"type": "object", "properties": {}}),
            }
        })
    return openai_tools


# ─── Claude Backend ───────────────────────────────────────────────────────────

class ClaudeBackend:
    def __init__(self):
        if not ANTHROPIC_API_KEY:
            console.print("[red]ERROR: ANTHROPIC_API_KEY not set in .env[/red]")
            sys.exit(1)
        self.client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        self.model = CLAUDE_MODEL
        self.name = f"Claude ({CLAUDE_MODEL})"

    def chat(self, messages: list, system: str, tools: list) -> dict:
        """Send messages and return a normalized response dict."""
        response = self.client.messages.create(
            model=self.model,
            max_tokens=4096,
            system=system,
            tools=tools,
            messages=messages,
        )

        text_parts = []
        tool_calls = []

        for block in response.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                tool_calls.append({
                    "id": block.id,
                    "name": block.name,
                    "input": block.input,
                })

        return {
            "text": "\n".join(text_parts),
            "tool_calls": tool_calls,
            "stop_reason": response.stop_reason,
            "raw": response.content,  # needed for messages history
        }

    def build_tool_result_message(self, tool_results: list[dict]) -> dict:
        """Build tool result message in Anthropic format."""
        return {
            "role": "user",
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": r["id"],
                    "content": r["content"],
                }
                for r in tool_results
            ]
        }

    def build_assistant_message(self, response: dict) -> dict:
        return {"role": "assistant", "content": response["raw"]}


# ─── Ollama Backend ───────────────────────────────────────────────────────────

class OllamaBackend:
    def __init__(self, model: str = None):
        self.host = OLLAMA_HOST.rstrip("/")
        self.model = model or OLLAMA_MODEL
        self.name = f"Ollama ({self.model}) @ {self.host}"

    def chat(self, messages: list, system: str, tools: list) -> dict:
        """Send messages to Ollama OpenAI-compatible API."""
        openai_messages = [{"role": "system", "content": system}] + messages
        openai_tools = _anthropic_to_openai_tools(tools)

        payload = {
            "model": self.model,
            "messages": openai_messages,
            "tools": openai_tools,
            "stream": False,
        }

        try:
            resp = requests.post(
                f"{self.host}/v1/chat/completions",
                json=payload,
                timeout=300,
            )
            resp.raise_for_status()
        except requests.exceptions.ConnectionError:
            console.print(f"[red]ERROR: Cannot connect to Ollama at {self.host}[/red]")
            sys.exit(1)
        except requests.exceptions.HTTPError as e:
            console.print(f"[red]Ollama HTTP error: {e}[/red]")
            sys.exit(1)

        data = resp.json()
        choice = data["choices"][0]
        message = choice["message"]

        text = message.get("content") or ""
        tool_calls = []

        for tc in message.get("tool_calls") or []:
            fn = tc.get("function", {})
            raw_args = fn.get("arguments", "{}")
            try:
                args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
            except json.JSONDecodeError:
                args = {}
            tool_calls.append({
                "id": tc.get("id", f"call_{fn.get('name','')}"),
                "name": fn.get("name", ""),
                "input": args,
            })

        stop_reason = "tool_use" if tool_calls else "end_turn"

        return {
            "text": text,
            "tool_calls": tool_calls,
            "stop_reason": stop_reason,
            "raw": message,
        }

    def build_tool_result_message(self, tool_results: list[dict]) -> dict:
        """Build tool result message in OpenAI format."""
        # Return one message per tool result (OpenAI format)
        # We concatenate all into a single user message for simplicity
        parts = []
        for r in tool_results:
            parts.append(f"[Tool: {r['name']}]\n{r['content']}")
        return {
            "role": "tool",
            "content": "\n\n".join(parts),
            "tool_call_id": tool_results[0]["id"] if tool_results else "0",
        }

    def build_assistant_message(self, response: dict) -> dict:
        raw = response["raw"]
        msg = {"role": "assistant", "content": raw.get("content") or ""}
        if response["tool_calls"]:
            msg["tool_calls"] = [
                {
                    "id": tc["id"],
                    "type": "function",
                    "function": {
                        "name": tc["name"],
                        "arguments": json.dumps(tc["input"]),
                    }
                }
                for tc in response["tool_calls"]
            ]
        return msg

    def available_models(self) -> list[str]:
        """Query Ollama for available models."""
        try:
            resp = requests.get(f"{self.host}/api/tags", timeout=10)
            resp.raise_for_status()
            return [m["name"] for m in resp.json().get("models", [])]
        except Exception:
            return []


# ─── Interactive LLM Selector ─────────────────────────────────────────────────

def select_llm(llm_flag: str = None, model_flag: str = None) -> ClaudeBackend | OllamaBackend:
    """Interactive LLM selector. Returns the chosen backend."""

    # Non-interactive: --llm flag provided
    if llm_flag:
        if llm_flag.lower() == "claude":
            return ClaudeBackend()
        elif llm_flag.lower() == "ollama":
            return OllamaBackend(model=model_flag)
        else:
            console.print(f"[red]Unknown --llm value: {llm_flag}. Use 'claude' or 'ollama'[/red]")
            sys.exit(1)

    # Fetch Ollama models for the menu
    probe = OllamaBackend()
    ollama_models = probe.available_models()

    # Build menu
    options = []
    options.append(("claude", CLAUDE_MODEL, "☁️  Anthropic API"))
    for m in ollama_models:
        default_tag = " [default]" if m == OLLAMA_MODEL else ""
        options.append(("ollama", m, f"🖥️  Ollama{default_tag}"))

    table = Table(title="SniperSAN — LLM Selector", box=box.ROUNDED, border_style="magenta")
    table.add_column("#", style="cyan", width=4)
    table.add_column("Model", style="bold white")
    table.add_column("Backend", style="dim")

    for i, (backend, model, label) in enumerate(options, 1):
        table.add_row(str(i), model, label)

    console.print()
    console.print(table)

    # Default = first Ollama model matching OLLAMA_MODEL, else 1 (Claude)
    default_idx = 1
    for i, (backend, model, _) in enumerate(options, 1):
        if backend == "ollama" and model == OLLAMA_MODEL:
            default_idx = i
            break

    choice = Prompt.ask(
        f"Select LLM",
        default=str(default_idx),
    )

    try:
        idx = int(choice) - 1
        backend, model, _ = options[idx]
    except (ValueError, IndexError):
        console.print("[red]Invalid selection, using default.[/red]")
        backend, model, _ = options[default_idx - 1]

    if backend == "claude":
        return ClaudeBackend()
    else:
        return OllamaBackend(model=model)
