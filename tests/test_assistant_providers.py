# Run directly (python tests/test_assistant_providers.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The three provider SDKs (anthropic, openai, google-genai) against small HTTP servers in this file that answer with each API's
# own shape: Test and the model list, a refused key, a host that does not answer, a turn with a tool call and the answer, what
# goes back in the second request (Claude's thinking block unchanged, OpenAI's reasoning item, Gemini's thought signature), the
# usage and cost, and a refusal. Needs the three SDKs installed (requirements.lock).
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
import base64, json, os, socket, sys, threading, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "aip%d.db" % int(time.time() * 1000)); os.environ["APPDATA"] = SP
for k in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "ALL_PROXY", "all_proxy"):
    os.environ.pop(k, None)
os.environ["NO_PROXY"] = "127.0.0.1,localhost"
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from core import audit, db, orgs
db.init()
from core import assistant as AI
from core.assistant import agent, prices, providers, store, tools as T
from drivers.base import Result

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

missing = []
for mod in ("anthropic", "openai", "google.genai"):
    try:
        __import__(mod)
    except ImportError:
        missing.append(mod)
check("the three SDKs are installed (anthropic, openai, google-genai)", not missing, missing)
if missing:
    print(f"\n{ok} passed, {bad} failed")
    sys.exit(1)

GOOD = "test-key-GOOD-1234567890"
acme = orgs.create("Acme", "acme")
db.set_home(acme)
with db.within(acme):
    db.save_device(dict(name="core-sw1", vendor="cisco", host="10.0.0.1", port=0, platform="cisco_ios", username="admin", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None, tags=""))
    db.save_run([Result("core-sw1", "cpu", "FAIL", "95", "CPU at 95%", 95.0)])


class Fake(ThreadingHTTPServer):
    """One provider's API on 127.0.0.1: the handler records every request (headers and JSON body) and answers from a script."""
    daemon_threads = True

    def __init__(self, handler):
        super().__init__(("127.0.0.1", 0), handler)
        self.requests, self.script, self.lock = [], [], threading.Lock()
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_address[1]}"

    def next_step(self):
        with self.lock:
            return self.script.pop(0) if self.script else ("text", "No script left.")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}") if n else {}
    def send_json(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(data))); self.end_headers()
        self.wfile.write(data)
    def start_sse(self):
        self.send_response(200); self.send_header("Content-Type", "text/event-stream"); self.send_header("Cache-Control", "no-cache")
        self.send_header("Transfer-Encoding", "chunked"); self.end_headers()
    def sse(self, obj, event=None):
        text = (f"event: {event}\n" if event else "") + "data: " + json.dumps(obj) + "\n\n"
        raw = text.encode()
        self.wfile.write(f"{len(raw):X}\r\n".encode() + raw + b"\r\n"); self.wfile.flush()
    def end_sse(self):
        self.wfile.write(b"0\r\n\r\n"); self.wfile.flush()
    def record(self, body):
        self.server.requests.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}, "body": body})


# ---------------------------------------------------------------- Claude: /v1/models, /v1/messages (SSE)
class ClaudeHandler(Handler):
    def authed(self):
        if self.headers.get("x-api-key") == GOOD or self.headers.get("Authorization") == f"Bearer {GOOD}":
            return True
        self.send_json(401, {"type": "error", "error": {"type": "authentication_error", "message": "invalid x-api-key"}})
        return False
    def do_GET(self):
        self.record({})
        if not self.authed(): return
        if self.path.startswith("/v1/models"):
            self.send_json(200, {"data": [{"type": "model", "id": "claude-opus-5-5", "display_name": "Claude Opus 5.5", "created_at": "2026-09-21T00:00:00Z", "lifecycle": "active"},
                                          {"type": "model", "id": "claude-sonnet-5-5", "display_name": "Claude Sonnet 5.5", "created_at": "2026-09-28T00:00:00Z", "lifecycle": "active"},
                                          {"type": "model", "id": "claude-3-haiku-20240307", "display_name": "Claude 3 Haiku", "created_at": "2024-03-07T00:00:00Z", "lifecycle": "retired"}],
                                 "first_id": "claude-opus-5-5", "has_more": False, "last_id": "claude-3-haiku-20240307"})
        else:
            self.send_json(404, {"type": "error", "error": {"type": "not_found_error", "message": "no"}})
    def do_POST(self):
        body = self.body(); self.record(body)
        if not self.authed(): return
        step = self.server.next_step()
        self.start_sse()
        model = step[2] if step[0] == "text" and len(step) > 2 else body.get("model", "claude-opus-5-5")
        self.sse({"type": "message_start", "message": {"id": "msg_1", "type": "message", "role": "assistant", "model": model, "content": [], "stop_reason": None, "stop_sequence": None,
                                                        "usage": {"input_tokens": 1200, "output_tokens": 1}}}, "message_start")
        if step[0] == "tool":
            self.sse({"type": "content_block_start", "index": 0, "content_block": {"type": "thinking", "thinking": "", "signature": ""}}, "content_block_start")
            self.sse({"type": "content_block_delta", "index": 0, "delta": {"type": "thinking_delta", "thinking": ""}}, "content_block_delta")
            self.sse({"type": "content_block_delta", "index": 0, "delta": {"type": "signature_delta", "signature": "SIGNATURE-" + step[1]}}, "content_block_delta")
            self.sse({"type": "content_block_stop", "index": 0}, "content_block_stop")
            self.sse({"type": "content_block_start", "index": 1, "content_block": {"type": "tool_use", "id": "toolu_" + step[1], "name": "latest_results", "input": {}}}, "content_block_start")
            self.sse({"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": '{"device": '}}, "content_block_delta")
            self.sse({"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": '"core-sw1"}'}}, "content_block_delta")
            self.sse({"type": "content_block_stop", "index": 1}, "content_block_stop")
            self.sse({"type": "message_delta", "delta": {"stop_reason": "tool_use", "stop_sequence": None}, "usage": {"input_tokens": 1200, "output_tokens": 80}}, "message_delta")
        elif step[0] == "text":
            self.sse({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}, "content_block_start")
            for piece in step[1].split("|"):
                self.sse({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": piece}}, "content_block_delta")
            self.sse({"type": "content_block_stop", "index": 0}, "content_block_stop")
            self.sse({"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None}, "usage": {"input_tokens": 1200, "output_tokens": 60}}, "message_delta")
        elif step[0] == "search":
            self.sse({"type": "content_block_start", "index": 0, "content_block": {"type": "server_tool_use", "id": "srvtoolu_1", "name": "web_search", "input": {}}}, "content_block_start")
            self.sse({"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": json.dumps({"query": step[1]})}}, "content_block_delta")
            self.sse({"type": "content_block_stop", "index": 0}, "content_block_stop")
            self.sse({"type": "content_block_start", "index": 1, "content_block": {"type": "web_search_tool_result", "tool_use_id": "srvtoolu_1",
                                                                                   "content": [{"type": "web_search_result", "url": ADVISORY, "title": "Cisco Security Advisory", "encrypted_content": "ENC", "page_age": None}]}}, "content_block_start")
            self.sse({"type": "content_block_stop", "index": 1}, "content_block_stop")
            self.sse({"type": "content_block_start", "index": 2, "content_block": {"type": "text", "text": "", "citations": []}}, "content_block_start")
            for piece in step[2].split("|"):
                self.sse({"type": "content_block_delta", "index": 2, "delta": {"type": "text_delta", "text": piece}}, "content_block_delta")
            self.sse({"type": "content_block_delta", "index": 2, "delta": {"type": "citations_delta", "citation": {"type": "web_search_result_location", "url": ADVISORY, "title": "Cisco Security Advisory",
                                                                                                                   "cited_text": "Affected", "encrypted_index": "IDX"}}}, "content_block_delta")
            self.sse({"type": "content_block_stop", "index": 2}, "content_block_stop")
            self.sse({"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None}, "usage": {"input_tokens": 1200, "output_tokens": 70, "server_tool_use": {"web_search_requests": 1, "web_fetch_requests": 0}}}, "message_delta")
        elif step[0] == "refusal":
            self.sse({"type": "message_delta", "delta": {"stop_reason": "refusal", "stop_sequence": None, "stop_details": {"category": "bio", "recommended_model": None}},
                      "usage": {"input_tokens": 1200, "output_tokens": 0}}, "message_delta")
        self.sse({"type": "message_stop"}, "message_stop")
        self.end_sse()


# ---------------------------------------------------------------- OpenAI: /v1/models, /v1/responses (SSE)
class OpenAIHandler(Handler):
    def authed(self):
        if self.headers.get("Authorization") == f"Bearer {GOOD}":
            return True
        self.send_json(401, {"error": {"message": "Incorrect API key provided", "type": "invalid_request_error", "param": None, "code": "invalid_api_key"}})
        return False
    def do_GET(self):
        self.record({})
        if not self.authed(): return
        if self.path.startswith("/v1/models"):
            self.send_json(200, {"object": "list", "data": [{"id": i, "object": "model", "created": 1, "owned_by": "openai"} for i in
                                                            ("gpt-6-luna", "gpt-6.1-sol", "gpt-6-astra", "gpt-image-2", "text-embedding-3-large", "gpt-realtime", "o3", "gpt-4.1-2025-04-14")]})
        else:
            self.send_json(404, {"error": {"message": "no", "type": "invalid_request_error"}})
    def response_obj(self, body, status, output, usage=None):
        return {"id": "resp_1", "object": "response", "created_at": 1_790_000_000, "status": status, "model": body.get("model", "gpt-6.1-sol"), "output": output,
                "usage": usage, "parallel_tool_calls": True, "tool_choice": "auto", "tools": body.get("tools", []), "error": None, "incomplete_details": None}
    def do_POST(self):
        body = self.body(); self.record(body)
        if not self.authed(): return
        step = self.server.next_step()
        self.start_sse()
        self.sse({"type": "response.created", "sequence_number": 0, "response": self.response_obj(body, "in_progress", [])}, "response.created")
        usage = {"input_tokens": 1000, "output_tokens": 50, "total_tokens": 1050, "input_tokens_details": {"cached_tokens": 0}, "output_tokens_details": {"reasoning_tokens": 20}}
        if step[0] == "tool":
            reasoning = {"type": "reasoning", "id": "rs_" + step[1], "summary": [], "encrypted_content": "ENC-" + step[1]}
            call = {"type": "function_call", "id": "fc_" + step[1], "call_id": "call_" + step[1], "name": "latest_results", "arguments": "", "status": "in_progress"}
            self.sse({"type": "response.output_item.added", "sequence_number": 1, "output_index": 0, "item": reasoning}, "response.output_item.added")
            self.sse({"type": "response.output_item.done", "sequence_number": 2, "output_index": 0, "item": reasoning}, "response.output_item.done")
            self.sse({"type": "response.output_item.added", "sequence_number": 3, "output_index": 1, "item": call}, "response.output_item.added")
            self.sse({"type": "response.function_call_arguments.delta", "sequence_number": 4, "item_id": call["id"], "output_index": 1, "delta": '{"device": '}, "response.function_call_arguments.delta")
            self.sse({"type": "response.function_call_arguments.done", "sequence_number": 5, "item_id": call["id"], "output_index": 1, "arguments": '{"device": "core-sw1"}'}, "response.function_call_arguments.done")
            done_call = dict(call, arguments='{"device": "core-sw1"}', status="completed")
            self.sse({"type": "response.output_item.done", "sequence_number": 6, "output_index": 1, "item": done_call}, "response.output_item.done")
            self.sse({"type": "response.completed", "sequence_number": 7, "response": self.response_obj(body, "completed", [reasoning, done_call], usage)}, "response.completed")
        elif step[0] == "text":
            text = step[1].replace("|", "")
            msg = {"type": "message", "id": "msg_1", "role": "assistant", "status": "completed", "content": [{"type": "output_text", "text": text, "annotations": []}]}
            self.sse({"type": "response.output_item.added", "sequence_number": 1, "output_index": 0, "item": dict(msg, content=[], status="in_progress")}, "response.output_item.added")
            for piece in step[1].split("|"):
                self.sse({"type": "response.output_text.delta", "sequence_number": 2, "item_id": "msg_1", "output_index": 0, "content_index": 0, "delta": piece, "logprobs": []}, "response.output_text.delta")
            self.sse({"type": "response.output_item.done", "sequence_number": 3, "output_index": 0, "item": msg}, "response.output_item.done")
            self.sse({"type": "response.completed", "sequence_number": 4, "response": self.response_obj(body, "completed", [msg], dict(usage, output_tokens=60))}, "response.completed")
        elif step[0] == "search":
            call = {"type": "web_search_call", "id": "ws_1", "status": "completed", "action": {"type": "search", "query": step[1], "sources": [{"type": "url", "url": ADVISORY}]}}
            self.sse({"type": "response.output_item.added", "sequence_number": 1, "output_index": 0, "item": dict(call, status="in_progress")}, "response.output_item.added")
            self.sse({"type": "response.output_item.done", "sequence_number": 2, "output_index": 0, "item": call}, "response.output_item.done")
            text = step[2].replace("|", "")
            msg = {"type": "message", "id": "msg_1", "role": "assistant", "status": "completed",
                   "content": [{"type": "output_text", "text": text, "annotations": [{"type": "url_citation", "url": ADVISORY, "title": "Cisco Security Advisory", "start_index": 0, "end_index": 8}]}]}
            for piece in step[2].split("|"):
                self.sse({"type": "response.output_text.delta", "sequence_number": 3, "item_id": "msg_1", "output_index": 1, "content_index": 0, "delta": piece, "logprobs": []}, "response.output_text.delta")
            self.sse({"type": "response.output_item.done", "sequence_number": 4, "output_index": 1, "item": msg}, "response.output_item.done")
            self.sse({"type": "response.completed", "sequence_number": 5, "response": self.response_obj(body, "completed", [call, msg], dict(usage, output_tokens=70))}, "response.completed")
        elif step[0] == "refusal":
            msg = {"type": "message", "id": "msg_2", "role": "assistant", "status": "completed", "content": [{"type": "refusal", "refusal": "I can't help with that."}]}
            self.sse({"type": "response.output_item.done", "sequence_number": 1, "output_index": 0, "item": msg}, "response.output_item.done")
            self.sse({"type": "response.completed", "sequence_number": 2, "response": self.response_obj(body, "completed", [msg], usage)}, "response.completed")
        self.end_sse()


# ---------------------------------------------------------------- Gemini: /v1beta/models, /v1beta/models/<m>:streamGenerateContent (SSE)
SIG = base64.b64encode(b"thought-signature-bytes-\x00\x01\x02").decode()

class GeminiHandler(Handler):
    def authed(self):
        if self.headers.get("x-goog-api-key") == GOOD:
            return True
        self.send_json(400, {"error": {"code": 400, "message": "API key not valid. Please pass a valid API key.", "status": "INVALID_ARGUMENT"}})
        return False
    def do_GET(self):
        self.record({})
        if not self.authed(): return
        if "/models" in self.path:
            self.send_json(200, {"models": [{"name": "models/gemini-3.8-flash", "displayName": "Gemini 3.8 Flash", "supportedGenerationMethods": ["generateContent", "countTokens"]},
                                            {"name": "models/gemini-2.5-flash", "displayName": "Gemini 2.5 Flash", "supportedGenerationMethods": ["generateContent"]},
                                            {"name": "models/gemini-embedding-001", "displayName": "Gemini Embedding", "supportedGenerationMethods": ["embedContent"]},
                                            {"name": "models/imagen-4", "displayName": "Imagen 4", "supportedGenerationMethods": ["predict"]}]})
        else:
            self.send_json(404, {"error": {"code": 404, "message": "no", "status": "NOT_FOUND"}})
    def do_POST(self):
        body = self.body(); self.record(body)
        if not self.authed(): return
        body["_model"] = self.path.split("/models/")[-1].split(":")[0] if "/models/" in self.path else "gemini-3.8-flash"
        if getattr(self.server, "refuse_mix", False) and any("googleSearch" in json.dumps(camel(t)) for t in body.get("tools") or []):
            self.send_json(400, {"error": {"code": 400, "message": "Multiple tools are supported only when they are all search tools.", "status": "INVALID_ARGUMENT"}})
            return
        step = self.server.next_step()
        self.start_sse()
        usage = {"promptTokenCount": 900, "candidatesTokenCount": 40, "thoughtsTokenCount": 30, "totalTokenCount": 970}
        if step[0] == "search":
            pieces = step[2].split("|")
            for i, piece in enumerate(pieces):
                chunk = {"candidates": [{"content": {"role": "model", "parts": [{"text": piece}]}, "index": 0}], "modelVersion": body.get("_model", "gemini-3.8-flash")}
                if i == len(pieces) - 1:
                    chunk["candidates"][0]["finishReason"] = "STOP"
                    chunk["candidates"][0]["groundingMetadata"] = {"webSearchQueries": [step[1]], "groundingChunks": [{"web": {"uri": ADVISORY, "title": "Cisco Security Advisory"}}]}
                    chunk["usageMetadata"] = dict(usage, candidatesTokenCount=70, totalTokenCount=1000)
                self.sse(chunk)
        elif step[0] == "tool":
            self.sse({"candidates": [{"content": {"role": "model", "parts": [{"functionCall": {"name": "latest_results", "args": {"device": "core-sw1"}}, "thoughtSignature": SIG}]},
                                      "index": 0, "finishReason": "STOP"}], "usageMetadata": usage, "modelVersion": "gemini-3.8-flash"})
        elif step[0] == "text":
            pieces = step[1].split("|")
            for i, piece in enumerate(pieces):
                chunk = {"candidates": [{"content": {"role": "model", "parts": [{"text": piece}]}, "index": 0}], "modelVersion": "gemini-3.8-flash"}
                if i == len(pieces) - 1:
                    chunk["candidates"][0]["finishReason"] = "STOP"
                    chunk["usageMetadata"] = dict(usage, candidatesTokenCount=60, totalTokenCount=990)
                self.sse(chunk)
        elif step[0] == "refusal":
            self.sse({"candidates": [{"finishReason": "SAFETY", "index": 0, "safetyRatings": []}], "usageMetadata": usage, "modelVersion": "gemini-3.8-flash"})
        self.end_sse()


ADVISORY = "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-2026-0235"


def closed_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    return f"http://127.0.0.1:{port}"


def run(provider, question, screen=None):
    events = []
    with db.within(acme):
        cid = store.create(provider, AI.model_for(provider), question)
    done = agent.run_turn(cid, acme, question, screen or {"section": "Inventory"}, lambda k, p: events.append((k, p)))
    return cid, events, done


def exercise(pid, server, model, display, model_list, bad_models, reads):
    """The same story for each provider: Test, a refused key, no answer, a turn with a tool call, the second request, a refusal."""
    print(f"== {AI.PROVIDERS[pid]['label']}")
    AI.BASE_URLS[pid] = server.url + ("/v1" if pid == "openai" else "")
    db.set_setting("ai_provider", pid)
    AI.set_key(pid, GOOD)
    AI.set_model(pid, model)
    r = AI.test_connection(pid, GOOD, model)
    check("Test with the key: the approved line with the model's name", r["ok"] and r["text"] == f"Connected: {display}." and r["model"] == display, r)
    check("the model list comes from the provider, the ones that take a conversation only", [m for m, _ in r["models"]] == model_list and not any(b in dict(r["models"]) for b in bad_models), r["models"])
    r = AI.test_connection(pid, "wrong-key", model)
    check("a wrong key: Not connected: the API key was refused.", r["text"] == "Not connected: the API key was refused." and not r["ok"], r)
    AI.BASE_URLS[pid] = closed_port() + ("/v1" if pid == "openai" else "")
    r = AI.test_connection(pid, GOOD, model)
    check("nothing listening: Not connected: no answer from <host>.", r["text"] == f"Not connected: no answer from {AI.PROVIDERS[pid]['host']}." and not r["ok"], r)
    AI.BASE_URLS[pid] = server.url + ("/v1" if pid == "openai" else "")
    server.requests.clear()
    server.script[:] = [("tool", "1"), ("text", "core-sw1 is |failing on CPU.")]
    cid, events, done = run(pid, "What is wrong with core-sw1?")
    kinds = [k for k, _ in events]
    check("a turn: the tool step, the streamed text, done", kinds[0] == "tool" and kinds.count("text") == 2 and kinds[-1] == "done" and events[0][1] == "Reading core-sw1's latest results…", events)
    check("the text as streamed", done is not None and done["text"] == "core-sw1 is failing on CPU.", done)
    check("tokens from both rounds and the cost for the model", done["tokens_in"] == reads["tokens_in"] and done["tokens_out"] == reads["tokens_out"]
          and abs(done["cost"] - prices.cost(done["model"], reads["tokens_in"], reads["tokens_out"])) < 1e-9 and done["priced"], done)
    posts = [q for q in server.requests if q["body"]]
    check("two requests went out, both to the right path, with the key", len(posts) == 2 and all(reads["path"] in q["path"] for q in posts) and reads["key_header"](posts[0]["headers"]))
    reads["check_first"](posts[0])
    reads["check_second"](posts[1])
    with db.within(acme):
        conv = store.get(cid)
    check("the provider's own history is stored for the next question", len(conv["history"]) == reads["history_len"], len(conv["history"]))
    server.script[:] = [("text", "Still failing.")]
    events.clear()
    done = agent.run_turn(cid, acme, "And now?", {}, lambda k, p: events.append((k, p)))
    third = [q for q in server.requests if q["body"]][-1]
    check("the next question carries the whole conversation back (the earlier tool round included)", done["text"] == "Still failing." and reads["carries_all"](third["body"]), json.dumps(third["body"])[:400])
    server.script[:] = [("refusal",)]
    cid, events, done = run(pid, "Something it declines")
    check("a refusal is a normal end: the panel is told in words, the turn is kept", done is not None and done["note"] == AI.REFUSED and events[-1][0] == "done", (events, done))
    server.script[:] = [("search", "CVE-2026-0235 Catalyst 9300", "Affected: |17.09.04a and below.")]
    cid, events, done = run(pid, "Are these switches affected by CVE-2026-0235?")
    step = "Searching the web for CVE-2026-0235 Catalyst 9300…"
    if pid == "gemini":
        check("Gemini: the query is known only with the answer, so the step comes after it", [p for k, p in events if k == "tool"] == [] and done["after"] == ["Searched the web for CVE-2026-0235 Catalyst 9300…"], (events, done))
    else:
        check("the search is announced as it happens, before the text", events[0] == ("tool", step) and done["after"] == [], events)
    check("one search counted and priced, the page it rests on named", done["searches"] == 1 and done["sources"] == [("Cisco Security Advisory", ADVISORY)] and done["text"] == "Affected: 17.09.04a and below."
          and abs(done["cost"] - prices.cost(done["model"], done["tokens_in"], done["tokens_out"], 1)) < 1e-9 and prices.search_rate(done["model"]) > 0, done)
    with db.within(acme):
        db.set_home(acme)
        lines = [e["detail"] for e in audit.recent(5)]
        last = [t for t in store.turns(cid) if t["kind"] == "assistant"][-1]
    check("the audit line and the stored turn (searches and sources)", "searched the web: CVE-2026-0235 Catalyst 9300" in lines and last["searches"] == 1 and last["sources"] == [["Cisco Security Advisory", ADVISORY]], (lines, last))


# ---------------------------------------------------------------- Claude
claude = Fake(ClaudeHandler)
def claude_first(q):
    b, h = q["body"], q["headers"]
    check("Claude: streaming, tools with input_schema, effort from Depth, fallbacks default with its beta, no thinking block (on by default)",
          b.get("stream") is True and b["tools"][0]["input_schema"]["type"] == "object" and {t["name"] for t in b["tools"] if "input_schema" in t} == set(T.BY_NAME) - {"run_commands"}
          and [t["type"] for t in b["tools"] if "input_schema" not in t] == ["web_search_20260209", "web_fetch_20260209"]
          and b["output_config"] == {"effort": "medium"} and b["fallbacks"] == "default" and "server-side-fallback-2026-07-01" in h.get("anthropic-beta", "")
          and b["thinking"] == {"type": "adaptive", "block_binding": {"prefix_mismatch_behavior": "drop_block"}} and "thinking-binding-controls-2026-08-01" in h.get("anthropic-beta", "")
          and b["model"] == "claude-opus-5-5" and b["max_tokens"] >= 4096 and "Acme" in (b["system"] if isinstance(b["system"], str) else json.dumps(b["system"])), (b.keys(), h.get("anthropic-beta")))
def claude_second(q):
    m = q["body"]["messages"]
    check("Claude: the system prompt of the second request is byte for byte the first one's (the thinking block stays bound)", q["body"]["system"] == claude.requests[-2]["body"]["system"] if len(claude.requests) >= 2 else False)
    check("Claude: the second request has the assistant turn with the thinking block unchanged (signature included) and the tool_use, then the tool_result",
          m[0]["role"] == "user" and m[1]["role"] == "assistant" and m[1]["content"][0] == {"type": "thinking", "thinking": "", "signature": "SIGNATURE-1"}
          and m[1]["content"][1]["type"] == "tool_use" and m[1]["content"][1]["id"] == "toolu_1" and m[1]["content"][1]["input"] == {"device": "core-sw1"}
          and m[2]["role"] == "user" and m[2]["content"][0]["type"] == "tool_result" and m[2]["content"][0]["tool_use_id"] == "toolu_1" and "FAIL" in m[2]["content"][0]["content"], json.dumps(m)[:600])
exercise("claude", claude, "claude-opus-5-5", "Claude Opus 5.5", ["claude-opus-5-5", "claude-sonnet-5-5"], ["claude-3-haiku-20240307"],
         dict(tokens_in=2400, tokens_out=140, path="/v1/messages", key_header=lambda h: h.get("x-api-key") == GOOD or h.get("authorization") == f"Bearer {GOOD}",
              check_first=claude_first, check_second=claude_second, history_len=4,
              carries_all=lambda b: len(b["messages"]) == 5 and b["messages"][1]["content"][0]["signature"] == "SIGNATURE-1" and b["messages"][4]["content"].endswith("\nAnd now?")
              and b["system"] == claude.requests[0]["body"]["system"]))
claude.script[:] = [("search", "core-sw1 CVE-2026-0235", "Yes.")]
_cid, events, done = run("claude", "Is core-sw1 affected?")
check("Claude: a query that names a device is marked in the panel and the audit log", events[0] == ("tool", "Searching the web for core-sw1 CVE-2026-0235… (named a device)")
      and "searched the web: core-sw1 CVE-2026-0235 (named a device)" in [e["detail"] for e in audit.recent(5)], events[:1])
db.set_setting("ai_search", False)
claude.script[:] = [("text", "I cannot reach the internet.")]
_cid, events, done = run("claude", "CVE?")
body = [q for q in claude.requests if q["body"]][-1]["body"]
check("Claude: with the box unticked no search tool is offered and the instructions say so", all("input_schema" in t for t in body["tools"]) and "You cannot reach the internet." in body["system"] and done["searches"] == 0, body["tools"][-1])
db.set_setting("ai_search", True)
claude.script[:] = [("text", "Served by another model.", "claude-opus-4-8")]
_cid, events, done = run("claude", "fallback")
check("Claude: the model that served the answer (after a fallback) is the one priced", done["model"] == "claude-opus-4-8" and abs(done["cost"] - prices.cost("claude-opus-4-8", 1200, 60)) < 1e-9, done)
with db.within(acme):
    check("Claude: a wrong tool input is parsed with json.loads and the tool answers in words", json.loads(T.run("latest_results", providers._args('{"device": "nope"}')))["error"].startswith("No device"))
check("Claude: the SDK's own errors become ours", isinstance(providers.Claude(GOOD)._wrap(type("AuthenticationError", (Exception,), {"status_code": 401})("x")), providers.KeyRefused)
      and isinstance(providers.Claude(GOOD)._wrap(type("APIConnectionError", (Exception,), {})("x")), providers.NoAnswer))

# ---------------------------------------------------------------- OpenAI
oa = Fake(OpenAIHandler)
def oa_first(q):
    b = q["body"]
    check("OpenAI: the Responses API with function tools, streaming, reasoning effort from Depth, nothing stored on the server, the system text as instructions",
          b.get("stream") is True and b["tools"][0]["type"] == "function" and b["tools"][0]["parameters"]["type"] == "object" and {t["name"] for t in b["tools"] if t["type"] == "function"} == set(T.BY_NAME) - {"run_commands"}
          and {"type": "web_search"} in b["tools"] and b["reasoning"] == {"effort": "medium"} and b.get("store") is False and "Acme" in b["instructions"] and b["model"] == "gpt-6.1-sol"
          and b["input"][0]["role"] == "user" and b["input"][0]["content"].endswith("\nWhat is wrong with core-sw1?"), (b.keys(), b.get("reasoning")))
def oa_second(q):
    i = q["body"]["input"]
    types = [x.get("type") for x in i]
    check("OpenAI: the second request replays the reasoning item (encrypted_content), the function_call and a function_call_output with the call id",
          types[1:] == ["reasoning", "function_call", "function_call_output"] and i[1]["encrypted_content"] == "ENC-1" and i[2]["call_id"] == "call_1" and i[2]["arguments"] == '{"device": "core-sw1"}'
          and i[3]["call_id"] == "call_1" and "FAIL" in i[3]["output"], json.dumps(i)[:600])
exercise("openai", oa, "gpt-6.1-sol", "GPT-6.1 Sol", ["gpt-6-astra", "gpt-6-luna", "gpt-6.1-sol", "o3"], ["gpt-image-2", "text-embedding-3-large", "gpt-realtime", "gpt-4.1-2025-04-14"],
         dict(tokens_in=2000, tokens_out=110, path="/v1/responses", key_header=lambda h: h.get("authorization") == f"Bearer {GOOD}",
              check_first=oa_first, check_second=oa_second, history_len=5,
              carries_all=lambda b: len(b["input"]) == 6 and b["input"][1]["type"] == "reasoning" and b["input"][5]["role"] == "user" and b["input"][5]["content"].endswith("\nAnd now?")))

# ---------------------------------------------------------------- Gemini
gem = Fake(GeminiHandler)
def camel(obj):
    """The SDK writes some fields in snake_case and some in camelCase; Google's API takes both, so the checks read both."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            parts = k.split("_")
            out[parts[0] + "".join(p[:1].upper() + p[1:] for p in parts[1:])] = camel(v)
        return out
    if isinstance(obj, list):
        return [camel(v) for v in obj]
    return obj

def gem_first(q):
    b = camel(q["body"])
    cfg = b.get("generationConfig", {})
    decls = next(t["functionDeclarations"] for t in b["tools"] if "functionDeclarations" in t)
    check("Gemini: Google Search rides beside the function declarations", len(b["tools"]) == 2 and any("googleSearch" in t for t in b["tools"]), b["tools"])
    schema = decls[0].get("parametersJsonSchema") or decls[0].get("parameters") or {}
    check("Gemini: generateContent streamed, function declarations with JSON schemas, thinking level from Depth, the system instruction, automatic calling off",
          ":streamGenerateContent" in q["path"] and "alt=sse" in q["path"] and {d["name"] for d in decls} == set(T.BY_NAME) - {"run_commands"} and schema.get("type") == "object"
          and cfg.get("thinkingConfig", {}).get("thinkingLevel") == "MEDIUM" and "Acme" in json.dumps(b.get("systemInstruction")) and b["contents"][0]["role"] == "user",
          (q["path"], json.dumps({k: v for k, v in b.items() if k not in ("contents", "systemInstruction")})[:900]))
def gem_second(q):
    c = camel(q["body"])["contents"]
    check("Gemini: the second request has the model turn with the functionCall and its thought signature unchanged, then the functionResponse",
          c[1]["role"] == "model" and c[1]["parts"][0]["functionCall"]["name"] == "latest_results" and c[1]["parts"][0].get("thoughtSignature") == SIG
          and c[2]["role"] in ("tool", "user") and c[2]["parts"][0]["functionResponse"]["name"] == "latest_results" and "FAIL" in json.dumps(c[2]["parts"][0]["functionResponse"]["response"]), json.dumps(c)[:600])
exercise("gemini", gem, "gemini-3.8-flash", "Gemini 3.8 Flash", ["gemini-3.8-flash", "gemini-2.5-flash"], ["gemini-embedding-001", "imagen-4"],
         dict(tokens_in=1800, tokens_out=160, path=":streamGenerateContent", key_header=lambda h: h.get("x-goog-api-key") == GOOD,
              check_first=gem_first, check_second=gem_second, history_len=4,
              carries_all=lambda b: len(b["contents"]) == 5 and camel(b)["contents"][1]["parts"][0].get("thoughtSignature") == SIG and b["contents"][4]["parts"][0]["text"].endswith("\nAnd now?")))

gem.refuse_mix = True
gem.script[:] = [("text", "From what I know, yes.")]
_cid, events, done = run("gemini", "Affected by CVE-2026-0235?")
bodies = [q["body"] for q in gem.requests if q["body"]][-2:]
check("Gemini: a model that refuses the mix is asked again without search, and the note says so", done["text"] == "From what I know, yes." and done["note"] == "Search was not available with this model."
      and len(bodies[0]["tools"]) == 2 and len(bodies[1]["tools"]) == 1 and events[-1][0] == "done", (done, [len(b["tools"]) for b in bodies]))
gem.refuse_mix = False
AI.set_model("gemini", "gemini-2.5-flash")
gem.script[:] = [("search", "CVE-2026-0235", "Yes.")]
_cid, events, done = run("gemini", "Affected?")
check("Gemini 2.5: one answer that searched is one billable search at its own rate", done["model"] == "gemini-2.5-flash" and done["searches"] == 1 and abs(done["cost"] - prices.cost("gemini-2.5-flash", done["tokens_in"], done["tokens_out"], 1)) < 1e-9
      and abs(prices.search_rate("gemini-2.5-flash") - 0.035) < 1e-9 and abs(prices.search_rate("gemini-3.8-flash") - 0.014) < 1e-9, done)

print("== the three SDKs ship with Toner")
import importlib.metadata as md
for pkg in ("anthropic", "openai", "google-genai"):
    check(f"{pkg} is installed and pinned in requirements.lock", md.version(pkg) and f"{pkg}==" in open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "requirements.lock"), encoding="utf-8").read())

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
