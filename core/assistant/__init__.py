"""The Assistant: an AI agent inside Toner that reads Toner's own data through tools Toner defines (tools.py), backed by Claude,
OpenAI or Gemini through their official SDKs (providers.py), one provider and API key per installation (Settings > AI), one
conversation list per organization (store.py), a monthly spend limit across every organization, and prices per model (prices.py).

The key lives in the vault under service:ai-<provider>; the settings hold only the provider, model, depth and limit.
"""
import threading

import keyring

from core import db
from core import quiet

PROVIDERS = {"claude": {"label": "Claude", "host": "api.anthropic.com", "default_model": "claude-opus-5-5"},
             "openai": {"label": "OpenAI", "host": "api.openai.com", "default_model": "gpt-6.1-sol"},
             "gemini": {"label": "Gemini", "host": "generativelanguage.googleapis.com", "default_model": "gemini-3.8-flash"}}
DEPTHS = [("quick", "Quick"), ("normal", "Normal"), ("thorough", "Thorough")]
BASE_URLS = {}                   # provider -> another address (the tests point the SDKs at servers of their own)

# The sentences the panel shows (approved wording). {limit} is the installation's monthly limit.
LIMIT_TEXT = "This organization's monthly spend limit (USD {limit}) is reached. Raise it under Settings > AI."
CONNECTED = "Connected: {model}."
KEY_REFUSED = "Not connected: the API key was refused."
NO_ANSWER = "Not connected: no answer from {host}."
NOT_CONNECTED = "Not connected: {why}."
STRIP_ON, STRIP_OFF = "Assistant: connected", "Assistant: not connected"
REFUSED = "The provider declined to answer this question."
CUT_SHORT = "The answer was cut short at the provider's length limit."
TOO_MANY_STEPS = "The Assistant stopped after many steps without a final answer. Ask again more narrowly."


# ---------------------------------------------------------------- settings
def provider_id():
    p = db.get_setting("ai_provider")
    return p if p in PROVIDERS else "claude"


def commands_allowed():
    """Settings > AI: whether the Assistant may run show commands on devices (off unless switched on)."""
    return bool(db.get_setting("ai_run_commands"))


def search_allowed():
    """Settings > AI: whether the Assistant may search the internet through the provider's own search (on unless switched off)."""
    return bool(db.get_setting("ai_search"))


def model_for(provider=None):
    provider = provider or provider_id()
    return (db.get_setting("ai_model") or {}).get(provider) or PROVIDERS[provider]["default_model"]


def set_model(provider, model):
    models = dict(db.get_setting("ai_model") or {})
    models[provider] = model
    db.set_setting("ai_model", models)


def depth():
    d = db.get_setting("ai_depth")
    return d if d in dict(DEPTHS) else "normal"


def spend_limit():
    try:
        return float(db.get_setting("ai_spend_limit") or 0)
    except (TypeError, ValueError):
        return 0.0


def limit_text():
    return LIMIT_TEXT.format(limit=money(spend_limit()))


def money(x):
    """'20' for 20.0, '14.90' for 14.9: whole dollars plain, cents when there are any."""
    return f"{x:.0f}" if abs(x - round(x)) < 0.005 else f"{x:.2f}"


def spend_reached():
    """True when this month's cost across every organization has reached the limit (a limit of 0 means no limit)."""
    from core.assistant import store
    limit = spend_limit()
    return limit > 0 and store.all_totals()["cost"] >= limit


# ---------------------------------------------------------------- the key
def key_name(provider=None):
    return f"service:ai-{provider or provider_id()}"


def key_names():
    return [key_name(p) for p in PROVIDERS]


def get_key(provider=None):
    try:
        return keyring.get_password(db.SERVICE, key_name(provider)) or ""
    except Exception:
        quiet.ignored()
        return ""


def has_key(provider=None):
    return bool(get_key(provider))


def set_key(provider, value):
    if value:
        db.set_secret(key_name(provider), value)
    else:
        db.delete_secret(key_name(provider))


# ---------------------------------------------------------------- providers
def make(provider=None, key=None, model=None, depth_=None, base_url=None):
    """A provider object for the stored (or given) provider, key, model and depth."""
    from core.assistant import providers
    provider = provider or provider_id()
    cls = providers.PROVIDERS[provider]
    return cls(key if key is not None else get_key(provider), model or model_for(provider), depth_ or depth(), base_url or BASE_URLS.get(provider))


def test_connection(provider, key, model=None):
    """Reach the provider with this key. Returns {'ok', 'text', 'models': [(id, display)], 'model': display name}; never raises."""
    from core.assistant import providers
    info = PROVIDERS[provider]
    prov = make(provider, key, model)
    try:
        models = prov.list_models()
        shown = dict(models).get(prov.model) or prov.display(prov.model)
        return {"ok": True, "text": CONNECTED.format(model=shown), "models": models, "model": shown}
    except providers.KeyRefused:
        return {"ok": False, "text": KEY_REFUSED, "models": [], "model": ""}
    except providers.NoAnswer:
        return {"ok": False, "text": NO_ANSWER.format(host=info["host"]), "models": [], "model": ""}
    except providers.ProviderError as e:
        return {"ok": False, "text": NOT_CONNECTED.format(why=str(e)), "models": [], "model": ""}
    except Exception as e:                                                # noqa: BLE001  (an SDK that is missing, for one)
        return {"ok": False, "text": NOT_CONNECTED.format(why=f"{type(e).__name__}: {e}"[:200]), "models": [], "model": ""}


# ---------------------------------------------------------------- the connection state the window shows
_state = {"connected": None, "text": "", "checked": False, "model": ""}     # connected: None (not checked yet or no key), True, False
_listeners = []
_lock = threading.Lock()


def state():
    with _lock:
        return dict(_state)


def connected():
    return state()["connected"] is True


def set_state(connected_, text="", model=""):
    with _lock:
        _state.update(connected=connected_, text=text, checked=True, model=model)
        listeners = list(_listeners)
    for fn in listeners:
        try:
            fn(connected_, text)
        except Exception:
            quiet.ignored()


def add_listener(fn):
    """fn(connected, text) is called (on the thread that found out) whenever the state changes."""
    with _lock:
        _listeners.append(fn)


def remove_listener(fn):
    with _lock:
        if fn in _listeners:
            _listeners.remove(fn)


def check_now():
    """Test the stored key on this thread and remember the answer. With no key stored: not connected, nothing asked."""
    provider = provider_id()
    if not has_key(provider):
        set_state(None, "")
        return state()
    result = test_connection(provider, get_key(provider), model_for(provider))
    set_state(result["ok"], result["text"], result["model"])
    return state()


def check_in_background(done=None):
    """What the window does at startup and after Settings > AI is saved: the same test as the Test button, off the main thread."""
    def work():
        try:
            check_now()
        except Exception:
            quiet.ignored()
            set_state(False, NOT_CONNECTED.format(why="the check failed"))
        if done:
            done()
    t = threading.Thread(target=work, daemon=True, name="assistant-check")
    t.start()
    return t
