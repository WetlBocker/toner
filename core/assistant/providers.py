"""The three providers behind the Assistant, through their official Python SDKs, behind one interface.

A provider is given a conversation (in its own message shape, kept by core/assistant/store.py) and Toner's tool definitions,
streams the model's text back as it arrives, and reports the tool calls the model asked for, the tokens it used and why it
stopped. The loop that runs the tools and asks again is in agent.py, written once for all three.

Shapes were checked against each provider's current documentation and SDK sources in October 2026:
- Claude: Messages API through client.beta.messages.stream; tools with input_schema; tool_use blocks answered with tool_result
  blocks; adaptive thinking is on by default on the Claude 5 models, Depth maps to output_config.effort; thinking blocks go back
  unchanged (their signature included); fallbacks="default" with the server-side-fallback-2026-07-01 beta; stop_reason
  "refusal" is a normal answer that declines.
- OpenAI: Responses API with function tools, streaming events (response.output_text.delta, response.completed); every output
  item (reasoning items included) goes back in the next input; results as function_call_output; Depth maps to reasoning.effort.
- Gemini: generate_content_stream with FunctionDeclaration / Tool, automatic function calling off; function_call parts answered
  with function_response parts; Depth maps to thinking_config.thinking_level; thought signatures go back unchanged.

The SDKs are imported inside each class, so Toner starts (and the rest of this package works) even when one is missing.
"""
import base64
import json
import threading

MAX_TOKENS = 16000             # the longest answer (or batch of tool calls) in one round
TIMEOUT = 180                  # seconds for one round; a model that thinks hard can take a while
TEST_TIMEOUT = 30


class ProviderError(Exception):
    """The provider could not be used; the message is for the person."""


class KeyRefused(ProviderError):
    """The API key was refused (401 / 403, or Gemini's 400 'API key not valid')."""


class NoAnswer(ProviderError):
    """The provider's host did not answer."""


class Cancelled(Exception):
    """Stop was pressed."""


class Reply:
    """One round's answer: the text (also streamed), the tool calls asked for, the tokens, why it stopped, and the provider's own
    message(s) to append to the history so the next round continues this one."""

    def __init__(self):
        self.text, self.calls, self.native = "", [], []       # calls: [(call id, tool name, arguments dict)]
        self.tokens_in = self.tokens_out = 0
        self.stop, self.model, self.refusal = "end", "", ""    # stop: end | tool | refusal | length


def _args(raw):
    """A tool's arguments as a dict, from the dict or JSON text the provider gave."""
    if isinstance(raw, dict):
        return raw
    try:
        parsed = json.loads(raw or "{}")
    except ValueError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _check(cancel):
    if cancel is not None and cancel.is_set():
        raise Cancelled()


class Provider:
    name = label = host = default_model = ""
    EFFORT = {"quick": "low", "normal": "medium", "thorough": "high"}

    def __init__(self, key, model=None, depth="normal", base_url=None):
        self.key, self.model, self.depth, self.base_url = key or "", model or self.default_model, depth or "normal", base_url

    # ---- what each provider writes
    def list_models(self):
        """[(id, display name)] from the provider's own list, the ones that take a conversation."""
        raise NotImplementedError

    def complete(self, system, history, tools, on_text, cancel=None):
        """One round: ask with the history and tools, stream text through on_text, return a Reply."""
        raise NotImplementedError

    def user_message(self, text):
        """The message(s) to append for what the person typed."""
        raise NotImplementedError

    def tool_results(self, reply, results):
        """The message(s) to append for the tools' answers: results = [((call id, name, args), text)]."""
        raise NotImplementedError

    # ---- shared
    def test(self):
        """Reach the provider with the key; returns the chosen model's display name. Raises KeyRefused / NoAnswer / ProviderError."""
        models = self.list_models()
        return dict(models).get(self.model) or self.display(self.model)

    @staticmethod
    def display(model_id):
        return model_id

    def _wrap(self, e):
        """Turn an SDK exception into one of ours, by its shape (status code and class name), without importing the SDK."""
        name = type(e).__name__
        status = getattr(e, "status_code", None) or getattr(e, "code", None)
        text = str(getattr(e, "message", "") or e)
        if "Authentication" in name or "PermissionDenied" in name or status in (401, 403):
            return KeyRefused("the API key was refused")
        if "Connection" in name or "Connect" in name or "Timeout" in name or "Transport" in name:
            return NoAnswer(f"no answer from {self.host}")
        if status == 429 or "RateLimit" in name:
            return ProviderError(f"{self.label} is rate limiting this key; try again in a moment")
        return ProviderError(text.strip().rstrip(".")[:300] or f"{self.label} answered with an error")


# =============================================================================== Claude
class Claude(Provider):
    name, label, host, default_model = "claude", "Claude", "api.anthropic.com", "claude-opus-5-5"
    BETAS = ["server-side-fallback-2026-07-01"]
    KEEP = ("text", "thinking", "redacted_thinking", "tool_use")       # blocks that go back into the history

    def _client(self, timeout=TIMEOUT):
        import anthropic
        kw = dict(api_key=self.key, timeout=timeout, max_retries=1)
        if self.base_url:
            kw["base_url"] = self.base_url
        return anthropic.Anthropic(**kw)

    def list_models(self):
        try:
            out = []
            for m in self._client(TEST_TIMEOUT).models.list(limit=100):
                if getattr(m, "lifecycle", "active") == "retired":
                    continue
                out.append((m.id, getattr(m, "display_name", "") or m.id))
            return out
        except Exception as e:                                           # noqa: BLE001
            raise self._wrap(e) from None

    @staticmethod
    def tool_defs(tools):
        return [{"name": t.name, "description": t.description, "input_schema": t.schema} for t in tools]

    def complete(self, system, history, tools, on_text, cancel=None):
        reply = Reply()
        kw = dict(model=self.model, max_tokens=MAX_TOKENS, system=system, messages=history, tools=self.tool_defs(tools),
                  output_config={"effort": self.EFFORT.get(self.depth, "medium")}, fallbacks="default", betas=self.BETAS)
        try:
            with self._client().beta.messages.stream(**kw) as stream:
                for text in stream.text_stream:
                    _check(cancel)
                    reply.text += text
                    on_text(text)
                message = stream.get_final_message()
        except Cancelled:
            raise
        except Exception as e:                                           # noqa: BLE001
            raise self._wrap(e) from None
        blocks = []
        for b in message.content:
            if b.type not in self.KEEP:
                continue                                                 # a fallback marker is not part of the conversation
            blocks.append(b.model_dump(mode="json", exclude_none=True))
            if b.type == "tool_use":
                reply.calls.append((b.id, b.name, _args(b.input)))
        reply.native = [{"role": "assistant", "content": blocks}] if blocks else []
        u = message.usage
        reply.tokens_in = (u.input_tokens or 0) + (getattr(u, "cache_creation_input_tokens", 0) or 0) + (getattr(u, "cache_read_input_tokens", 0) or 0)
        reply.tokens_out = u.output_tokens or 0
        reply.model = message.model or self.model
        stop = message.stop_reason
        if stop == "tool_use" and reply.calls:
            reply.stop = "tool"
        elif stop == "refusal":
            reply.stop = "refusal"
            details = getattr(message, "stop_details", None)
            reply.refusal = (getattr(details, "category", None) or "") if details is not None else ""
        elif stop in ("max_tokens", "model_context_window_exceeded"):
            reply.stop = "length"
        return reply

    def user_message(self, text):
        return [{"role": "user", "content": text}]

    def tool_results(self, reply, results):
        return [{"role": "user", "content": [{"type": "tool_result", "tool_use_id": call[0], "content": text} for call, text in results]}]


# =============================================================================== OpenAI
class OpenAI(Provider):
    name, label, host, default_model = "openai", "OpenAI", "api.openai.com", "gpt-6.1-sol"
    SKIP = ("realtime", "audio", "image", "tts", "transcri", "embedding", "moderation", "search", "codex", "cyber", "instruct", "dall", "whisper", "sora", "chat-latest")

    def _client(self, timeout=TIMEOUT):
        import openai
        kw = dict(api_key=self.key, timeout=timeout, max_retries=1)
        if self.base_url:
            kw["base_url"] = self.base_url
        return openai.OpenAI(**kw)

    def list_models(self):
        try:
            ids = [m.id for m in self._client(TEST_TIMEOUT).models.list()]
        except Exception as e:                                           # noqa: BLE001
            raise self._wrap(e) from None
        keep = [i for i in ids if (i.startswith("gpt-") or i.startswith("o")) and not any(s in i for s in self.SKIP) and "-20" not in i]
        keep.sort(key=lambda i: (not i.startswith("gpt-6"), not i.startswith("gpt-5"), i))
        return [(i, self.display(i)) for i in keep]

    @staticmethod
    def display(model_id):
        """'gpt-6.1-sol' -> 'GPT-6.1 Sol'."""
        head, _, rest = (model_id or "").partition("-")
        words = [w.capitalize() if w.isalpha() else w for w in rest.split("-")] if rest else []
        return (head.upper() if head.startswith("gpt") else head) + (("-" + words[0] + (" " + " ".join(words[1:]) if words[1:] else "")) if words else "")

    @staticmethod
    def tool_defs(tools):
        return [{"type": "function", "name": t.name, "description": t.description, "parameters": t.schema} for t in tools]

    def complete(self, system, history, tools, on_text, cancel=None):
        kw = dict(model=self.model, input=history, instructions=system, tools=self.tool_defs(tools), store=False, stream=True,
                  reasoning={"effort": self.EFFORT.get(self.depth, "medium")})
        try:
            return self._stream(kw, on_text, cancel)
        except Cancelled:
            raise
        except Exception as e:                                           # noqa: BLE001
            if getattr(e, "status_code", None) == 400 and "reasoning" in str(e).lower():
                kw.pop("reasoning", None)                                # a model with no reasoning setting
                try:
                    return self._stream(kw, on_text, cancel)
                except Exception as e2:                                  # noqa: BLE001
                    raise self._wrap(e2) from None
            raise self._wrap(e) from None

    def _stream(self, kw, on_text, cancel):
        reply, final = Reply(), None
        stream = self._client().responses.create(**kw)
        try:
            for event in stream:
                _check(cancel)
                kind = getattr(event, "type", "")
                if kind == "response.output_text.delta":
                    reply.text += event.delta
                    on_text(event.delta)
                elif kind in ("response.completed", "response.incomplete"):
                    final = event.response
                elif kind == "response.failed":
                    err = getattr(event.response, "error", None)
                    raise ProviderError(getattr(err, "message", None) or "the request failed")
                elif kind == "error":
                    raise ProviderError(getattr(event, "message", None) or "the request failed")
        finally:
            try:
                stream.close()
            except Exception:                                            # noqa: BLE001
                pass
        if final is None:
            raise ProviderError("the answer ended before it was complete")
        for item in final.output:
            reply.native.append(item.model_dump(mode="json", exclude_none=True))
            kind = getattr(item, "type", "")
            if kind == "function_call":
                reply.calls.append((item.call_id, item.name, _args(item.arguments)))
            elif kind == "message":
                for part in getattr(item, "content", None) or []:
                    if getattr(part, "type", "") == "refusal":
                        reply.stop, reply.refusal = "refusal", getattr(part, "refusal", "") or ""
        if getattr(final, "usage", None) is not None:
            reply.tokens_in, reply.tokens_out = final.usage.input_tokens or 0, final.usage.output_tokens or 0
        reply.model = getattr(final, "model", "") or self.model
        if reply.calls:
            reply.stop = "tool"
        elif reply.stop != "refusal" and getattr(final, "status", "completed") == "incomplete":
            reply.stop = "length"
        return reply

    def user_message(self, text):
        return [{"role": "user", "content": text}]

    def tool_results(self, reply, results):
        return [{"type": "function_call_output", "call_id": call[0], "output": text} for call, text in results]


# =============================================================================== Gemini
class Gemini(Provider):
    name, label, host, default_model = "gemini", "Gemini", "generativelanguage.googleapis.com", "gemini-3.8-flash"
    LEVEL = {"quick": "LOW", "normal": "MEDIUM", "thorough": "HIGH"}

    def _client(self, timeout=TIMEOUT):
        from google import genai
        from google.genai import types
        opts = {"timeout": timeout * 1000}
        if self.base_url:
            opts["base_url"] = self.base_url
        return genai.Client(api_key=self.key, http_options=types.HttpOptions(**opts))

    def list_models(self):
        try:
            out = []
            for m in self._client(TEST_TIMEOUT).models.list():
                name = (m.name or "").removeprefix("models/")
                actions = getattr(m, "supported_actions", None) or []
                if "gemini" in name and (not actions or "generateContent" in actions):
                    out.append((name, getattr(m, "display_name", "") or name))
            return out
        except Exception as e:                                           # noqa: BLE001
            raise self._wrap(e) from None

    def _wrap(self, e):
        status = getattr(e, "code", None) or getattr(e, "status_code", None)
        text = str(getattr(e, "message", "") or e)
        if status == 400 and "api key" in text.lower():
            return KeyRefused("the API key was refused")
        return super()._wrap(e)

    def _config(self, system, tools, thinking=True):
        from google.genai import types
        decls = [types.FunctionDeclaration(name=t.name, description=t.description, parameters_json_schema=t.schema) for t in tools]
        kw = dict(system_instruction=system, tools=[types.Tool(function_declarations=decls)] if decls else None,
                  automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True), max_output_tokens=MAX_TOKENS)
        if thinking:
            kw["thinking_config"] = types.ThinkingConfig(thinking_level=self.LEVEL.get(self.depth, "MEDIUM"))
        return types.GenerateContentConfig(**kw)

    def complete(self, system, history, tools, on_text, cancel=None):
        try:
            return self._stream(system, history, tools, on_text, cancel, thinking=True)
        except Cancelled:
            raise
        except Exception as e:                                           # noqa: BLE001
            if (getattr(e, "code", None) == 400) and "thinking" in str(e).lower():
                try:                                                     # a model that takes no thinking level: ask without one
                    return self._stream(system, history, tools, on_text, cancel, thinking=False)
                except Exception as e2:                                  # noqa: BLE001
                    raise self._wrap(e2) from None
            raise self._wrap(e) from None

    def _stream(self, system, history, tools, on_text, cancel, thinking):
        reply, parts, usage, finish = Reply(), [], None, ""
        client = self._client()
        contents = [self._content(c) for c in history]
        for chunk in client.models.generate_content_stream(model=self.model, contents=contents, config=self._config(system, tools, thinking)):
            _check(cancel)
            if getattr(chunk, "usage_metadata", None) is not None:
                usage = chunk.usage_metadata
            if getattr(chunk, "model_version", None):
                reply.model = chunk.model_version
            cand = chunk.candidates[0] if getattr(chunk, "candidates", None) else None
            if cand is None:
                continue
            if getattr(cand, "finish_reason", None):
                finish = str(cand.finish_reason).rsplit(".", 1)[-1].upper()
            for p in (cand.content.parts if cand.content and cand.content.parts else []):
                d = self._part_out(p)
                if d is None:
                    continue
                if "text" in d and not d.get("thought") and d["text"]:
                    reply.text += d["text"]
                    on_text(d["text"])
                if parts and "text" in d and "text" in parts[-1] and "thought_signature" not in d and "thought_signature" not in parts[-1] \
                        and not d.get("thought") and not parts[-1].get("thought"):
                    parts[-1]["text"] += d["text"]                       # one text part, not one per streamed piece
                else:
                    parts.append(d)
        for n, d in enumerate(parts):
            fc = d.get("function_call")
            if fc:
                reply.calls.append((fc.get("id") or f"call_{n}", fc["name"], _args(fc.get("args") or {})))
        if parts:
            reply.native = [{"role": "model", "parts": parts}]
        if usage is not None:
            reply.tokens_in = getattr(usage, "prompt_token_count", 0) or 0
            reply.tokens_out = (getattr(usage, "candidates_token_count", 0) or 0) + (getattr(usage, "thoughts_token_count", 0) or 0)
        reply.model = reply.model or self.model
        if reply.calls:
            reply.stop = "tool"
        elif finish in ("SAFETY", "PROHIBITED_CONTENT", "BLOCKLIST", "SPII", "IMAGE_SAFETY", "RECITATION"):
            reply.stop, reply.refusal = "refusal", finish.lower()
        elif finish == "MAX_TOKENS":
            reply.stop = "length"
        return reply

    # ---- the history is kept as plain JSON; parts are rebuilt into SDK types on the way in
    @staticmethod
    def _part_out(p):
        d = {}
        if getattr(p, "text", None) is not None:
            d["text"] = p.text
            if getattr(p, "thought", False):
                d["thought"] = True
        if getattr(p, "function_call", None) is not None:
            fc = p.function_call
            d["function_call"] = {"name": fc.name, "args": dict(fc.args or {}), **({"id": fc.id} if getattr(fc, "id", None) else {})}
        if getattr(p, "thought_signature", None):
            d["thought_signature"] = base64.b64encode(p.thought_signature).decode("ascii")
        return d or None

    @staticmethod
    def _content(c):
        from google.genai import types
        parts = []
        for d in c.get("parts", []):
            kw = {}
            if "text" in d:
                kw["text"] = d["text"]
                if d.get("thought"):
                    kw["thought"] = True
            if d.get("function_call"):
                fc = d["function_call"]
                kw["function_call"] = types.FunctionCall(name=fc["name"], args=fc.get("args") or {}, **({"id": fc["id"]} if fc.get("id") else {}))
            if d.get("function_response"):
                fr = d["function_response"]
                kw["function_response"] = types.FunctionResponse(name=fr["name"], response=fr.get("response") or {}, **({"id": fr["id"]} if fr.get("id") else {}))
            if d.get("thought_signature"):
                kw["thought_signature"] = base64.b64decode(d["thought_signature"])
            parts.append(types.Part(**kw))
        return types.Content(role=c.get("role", "user"), parts=parts)

    def user_message(self, text):
        return [{"role": "user", "parts": [{"text": text}]}]

    def tool_results(self, reply, results):
        parts = []
        for call, text in results:
            fr = {"name": call[1], "response": {"result": text}}
            if call[0] and not str(call[0]).startswith("call_"):
                fr["id"] = call[0]
            parts.append({"function_response": fr})
        return [{"role": "tool", "parts": parts}]


PROVIDERS = {cls.name: cls for cls in (Claude, OpenAI, Gemini)}
