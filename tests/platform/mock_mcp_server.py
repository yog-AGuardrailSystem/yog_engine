"""A tiny MCP-style server over stdio, for testing the proxy.  Newline-delimited JSON-RPC 2.0."""
import json
import sys

TOOLS = [{"name": "read_file"}, {"name": "shell"}, {"name": "fetch_url"}]
CALLS = []

for line in sys.stdin:
    if not line.strip():
        continue
    message = json.loads(line)
    method = message.get("method")
    if "id" not in message:                       # a notification: nothing to answer
        continue
    if method == "initialize":
        result = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "mock"}}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        params = message["params"]
        CALLS.append(params["name"])
        text = "x" * 5000 if params["name"] == "fetch_url" else f"ran {params['name']} {json.dumps(params.get('arguments'))}"
        meta = params.get("_meta")
        if meta and "yog_approval_token" in meta:
            text = "LEAK: the approval token reached the server"
        result = {"content": [{"type": "text", "text": text}], "isError": False}
    else:
        print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32601, "message": "no such method"}}), flush=True)
        continue
    print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}), flush=True)
