#!/usr/bin/env python3
"""See and drive the FerroCrypt desktop app from an agent or a terminal.

The app is built with the development-only `mcp` feature, which turns on
Slint's built-in MCP server (loopback HTTP) and replaces the file dialogs,
which the server cannot reach, with answers given by `pick`.

  run [--headless]    build and start the app with the server on (stays in front)
  pick [PATH]         the path the next file dialog chooses; no PATH cancels it
  shot [FILE]         save a PNG screenshot of the window and print its path
  tree                list the elements that have an id or accessibility data
  status              print the status line at the bottom of the window
  click TARGET [N]    click an element by qualified id (`AppWindow::start-ta`)
                      or by visible label (`Choose`); N picks one of several
  type [TEXT]         type TEXT into the focused field, one key at a time; without
                      TEXT, read it from stdin (keeps a passphrase out of history)
  call TOOL [JSON]    call any Slint MCP tool; the window handle is filled in

The server listens on port $SLINT_MCP_PORT (default 7992). Clients that speak
MCP can connect to it directly at http://127.0.0.1:PORT/mcp.
"""

import base64
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

DESKTOP_DIR = Path(__file__).resolve().parent.parent / "ferrocrypt-desktop"
STATE_DIR = DESKTOP_DIR / "target" / "mcp"
DIALOG_ANSWER_FILE = STATE_DIR / "dialog-answer"
DEFAULT_SCREENSHOT = STATE_DIR / "screenshot.png"
# Must match `automation::DIALOG_ANSWER_VAR` in the desktop crate.
DIALOG_ANSWER_VAR = "FERROCRYPT_DESKTOP_DIALOG_ANSWER"
PORT = os.environ.get("SLINT_MCP_PORT", "7992")
URL = f"http://127.0.0.1:{PORT}/mcp"
STATUS_ID = "AppWindow::notify-text"
# The most `get_element_tree` returns in one reply.
MAX_ELEMENTS = 1000


class Failure(Exception):
    pass


def rpc(method, params=None):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}})
    request = urllib.request.Request(
        URL, data=body.encode(), headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            reply = json.load(response)
    except urllib.error.HTTPError as e:
        raise Failure(f"{URL} answered HTTP {e.code}: {e.reason}") from None
    except TimeoutError:
        raise Failure(f"{URL} did not answer within 60 seconds") from None
    except urllib.error.URLError as e:
        raise Failure(
            f"No app answers at {URL} ({e.reason}): start it with `{sys.argv[0]} run`"
        ) from None

    if "error" in reply:
        raise Failure(reply["error"].get("message", str(reply["error"])))

    return reply["result"]


def tool(name, arguments=None):
    """Calls a tool and returns its content blocks; a tool error raises."""
    result = rpc("tools/call", {"name": name, "arguments": arguments or {}})
    content = result.get("content", [])
    if result.get("isError"):
        raise Failure(" ".join(b.get("text", "") for b in content))

    return content


def tool_json(name, arguments=None):
    return json.loads(tool(name, arguments)[0]["text"])


def window():
    handles = tool_json("list_windows").get("windowHandles", [])
    if not handles:
        raise Failure("The app has no window open")

    return handles[0]


def elements():
    root = tool_json("get_window_properties", {"windowHandle": window()})["rootElementHandle"]
    tree = tool_json("get_element_tree", {"elementHandle": root, "maxElements": MAX_ELEMENTS})
    if tree.get("truncated"):
        print(f"Warning: only the first {MAX_ELEMENTS} elements were read", file=sys.stderr)

    return tree.get("elements", [])


def ids_of(element):
    return [t["id"] for t in element.get("typeNamesAndIds", []) if t.get("id")]


def describe(element):
    names = element.get("typeNamesAndIds", [])
    type_name = names[0].get("typeName", "?") if names else "?"
    position = element.get("absolutePosition", {})
    size = element.get("size", {})
    parts = [f"#{element['handle'].get('index', '0')}", type_name, *ids_of(element)]
    for key, label in (("accessibleRole", "role"), ("accessibleValue", "value")):
        if key in element:
            parts.append(f"{label}={element[key]}")
    if "accessibleLabel" in element:
        parts.append(json.dumps(element["accessibleLabel"], ensure_ascii=False))
    for key, flag in (("accessibleEnabled", "enabled"), ("accessibleChecked", "checked")):
        if element.get(key):
            parts.append(flag)
    parts.append(
        f"@{position.get('x', 0):g},{position.get('y', 0):g} "
        f"{size.get('width', 0):g}x{size.get('height', 0):g}"
    )
    return " ".join(parts)


def find(target):
    if "::" in target:
        return [e for e in elements() if target in ids_of(e)]

    return [e for e in elements() if e.get("accessibleLabel") == target]


def cmd_run(args):
    env = dict(os.environ, SLINT_MCP_PORT=PORT)
    env[DIALOG_ANSWER_VAR] = str(DIALOG_ANSWER_FILE)
    if args == ["--headless"]:
        env["SLINT_BACKEND"] = "headless"
    elif args:
        raise Failure("usage: run [--headless]")

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    DIALOG_ANSWER_FILE.unlink(missing_ok=True)
    command = ["cargo", "run", "--features", "mcp"]
    os.chdir(DESKTOP_DIR)
    if os.name != "nt":
        os.execvpe(command[0], command, env)

    # Windows has no exec that keeps the console waiting on the new process.
    try:
        sys.exit(subprocess.call(command, env=env))
    except KeyboardInterrupt:
        sys.exit(130)


def cmd_pick(args):
    if len(args) > 1:
        raise Failure("usage: pick [PATH]")

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    answer = os.path.abspath(os.path.expanduser(args[0])) if args and args[0] else ""
    # Written aside and renamed into place, so the app never reads half of it.
    pending = DIALOG_ANSWER_FILE.with_name(DIALOG_ANSWER_FILE.name + ".pending")
    pending.write_text(answer + "\n" if answer else "")
    os.replace(pending, DIALOG_ANSWER_FILE)
    print(f"Next dialog: {answer or 'cancelled'}")


def cmd_shot(args):
    path = Path(args[0]).resolve() if args else DEFAULT_SCREENSHOT
    images = [b for b in tool("take_screenshot", {"windowHandle": window()}) if b["type"] == "image"]
    if not images:
        raise Failure("The screenshot reply holds no image")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(base64.b64decode(images[0]["data"]))
    print(path)


def cmd_tree(args):
    for element in elements():
        if ids_of(element) or any(k.startswith("accessible") for k in element):
            print(describe(element))


def cmd_status(args):
    found = find(STATUS_ID)
    print(found[0].get("accessibleLabel", "") if found else "")


def cmd_click(args):
    if len(args) not in (1, 2):
        raise Failure("usage: click TARGET [N]")

    matches = find(args[0])
    if not matches:
        raise Failure(f"No element matches {args[0]!r}; `tree` lists them")
    if len(args) == 1 and len(matches) > 1:
        listed = "\n".join(f"  {i}: {describe(e)}" for i, e in enumerate(matches, 1))
        raise Failure(f"{len(matches)} elements match {args[0]!r}; add N:\n{listed}")

    index = args[1] if len(args) == 2 else "1"
    if not index.isdigit() or not 1 <= int(index) <= len(matches):
        raise Failure(f"N must be between 1 and {len(matches)}")

    element = matches[int(index) - 1]
    tool("click_element", {"elementHandle": element["handle"]})
    print(f"Clicked {describe(element)}")


def cmd_type(args):
    if len(args) > 1:
        raise Failure("usage: type [TEXT]")

    text = args[0] if args else sys.stdin.read().rstrip("\r\n")
    handle = window()
    for char in text:
        tool("dispatch_key_event", {"windowHandle": handle, "text": char})


def cmd_call(args):
    if len(args) not in (1, 2):
        raise Failure("usage: call TOOL [JSON]")

    try:
        arguments = json.loads(args[1]) if len(args) == 2 else {}
    except json.JSONDecodeError as e:
        raise Failure(f"JSON arguments: {e}") from None
    if not isinstance(arguments, dict):
        raise Failure("JSON arguments must be an object")

    schemas = {t["name"]: t["inputSchema"] for t in rpc("tools/list")["tools"]}
    if args[0] not in schemas:
        raise Failure(f"Unknown tool {args[0]!r}; tools: {', '.join(sorted(schemas))}")
    if "windowHandle" in schemas[args[0]].get("properties", {}):
        arguments.setdefault("windowHandle", window())

    for block in tool(args[0], arguments):
        if block["type"] == "image":
            STATE_DIR.mkdir(parents=True, exist_ok=True)
            DEFAULT_SCREENSHOT.write_bytes(base64.b64decode(block["data"]))
            print(DEFAULT_SCREENSHOT)
        else:
            print(block.get("text", ""))


COMMANDS = {
    "run": cmd_run,
    "pick": cmd_pick,
    "shot": cmd_shot,
    "tree": cmd_tree,
    "status": cmd_status,
    "click": cmd_click,
    "type": cmd_type,
    "call": cmd_call,
}


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print(__doc__.strip())
        return 2

    try:
        COMMANDS[sys.argv[1]](sys.argv[2:])
    except Failure as e:
        print(e, file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
