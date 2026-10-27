"""What a turn costs: US dollars per million tokens, in and out, per model.

Read from each provider's published price list when this release was made (updated per release: Toner 1.9.0, October 2026).
A model that is not listed is priced like the nearest listed one of its family (the longest matching prefix), and a model
with no family at all costs nothing in the totals, which the Automation/AI page says. Thinking and reasoning tokens are billed as
output by every provider, so they are counted in tokens_out.

A web search is priced per provider (SEARCH, US dollars per search): Claude and OpenAI per search, Gemini 3 and newer per query
and Gemini 2.5 per answer that searched (the provider's own counting, which providers.py follows). Free allowances (Gemini's
5,000 a month or 1,500 a day) are not modelled, so the total shown can be above the bill.
"""

PRICES = {
    # Claude (platform.claude.com/docs/en/about-claude/pricing)
    "claude-fable-5-1": (10.0, 50.0), "claude-fable-5": (10.0, 50.0),
    "claude-opus-5-5": (4.0, 20.0), "claude-opus-5": (4.0, 20.0),
    "claude-sonnet-5-5": (2.0, 10.0), "claude-sonnet-5": (2.0, 10.0),
    "claude-haiku-5-5": (0.10, 0.50),
    "claude-opus-4-8": (4.0, 20.0), "claude-opus-4-7": (5.0, 25.0), "claude-opus-4-6": (5.0, 25.0), "claude-opus-4-5": (5.0, 25.0),
    "claude-sonnet-4-6": (3.0, 15.0), "claude-sonnet-4-5": (3.0, 15.0), "claude-haiku-4-5": (1.0, 5.0),
    # OpenAI (developers.openai.com/api/docs/pricing, standard tier)
    "gpt-6-astra": (10.0, 50.0), "gpt-6.1-sol": (2.0, 10.0), "gpt-6-sol": (2.0, 10.0), "gpt-6-luna": (0.10, 0.50),
    "gpt-5.6-sol": (4.0, 20.0), "gpt-5.6-terra": (2.0, 12.0), "gpt-5.6-luna": (0.20, 1.20),
    "gpt-5.5-pro": (30.0, 180.0), "gpt-5.5": (5.0, 30.0),
    "gpt-5.4-pro": (30.0, 180.0), "gpt-5.4-mini": (0.75, 4.50), "gpt-5.4-nano": (0.20, 1.25), "gpt-5.4": (2.50, 15.0),
    "gpt-5.2-pro": (21.0, 168.0), "gpt-5.2": (1.75, 14.0), "gpt-5.1": (1.25, 10.0),
    "gpt-5-pro": (15.0, 120.0), "gpt-5-mini": (0.25, 2.0), "gpt-5-nano": (0.05, 0.40), "gpt-5": (1.25, 10.0),
    "gpt-4.1-mini": (0.40, 1.60), "gpt-4.1-nano": (0.10, 0.40), "gpt-4.1": (2.0, 8.0),
    "o3-pro": (20.0, 80.0), "o3-mini": (1.10, 4.40), "o3": (2.0, 8.0), "o4-mini": (1.10, 4.40), "o1-pro": (150.0, 600.0), "o1": (15.0, 60.0),
    # Gemini (ai.google.dev/gemini-api/docs/pricing, paid tier, prompts up to 200k tokens; the Flash prices rise on 2027-01-01)
    "gemini-3.1-pro": (2.0, 12.0), "gemini-3-pro": (2.0, 12.0),
    "gemini-3.8-flash": (0.75, 3.75), "gemini-3.6-flash": (0.75, 3.75), "gemini-3-flash": (0.50, 3.0),
    "gemini-3.5-flash-lite": (0.10, 0.40), "gemini-3.1-flash-lite": (0.10, 0.40),
    "gemini-2.5-pro": (1.25, 10.0), "gemini-2.5-flash-lite": (0.10, 0.40), "gemini-2.5-flash": (0.30, 2.50),
}


SEARCH = {"claude": 0.010, "gpt": 0.010, "o": 0.010, "gemini-2.5": 0.035, "gemini": 0.014}


def search_rate(model):
    """US dollars per web search for the model's provider (0 when unknown)."""
    m = (model or "").lower().removeprefix("models/")
    best = max((k for k in SEARCH if m.startswith(k)), key=len, default=None)
    return SEARCH[best] if best else 0.0


def rate(model):
    """(USD per million tokens in, out) for a model id, or None when nothing is known about it."""
    m = (model or "").lower().removeprefix("models/")
    if m in PRICES:
        return PRICES[m]
    best = max((k for k in PRICES if m.startswith(k)), key=len, default=None)
    return PRICES[best] if best else None


def cost(model, tokens_in, tokens_out, searches=0):
    """What one turn cost, in US dollars (0 for a model with no known price), its web searches included."""
    r = rate(model)
    if not r:
        return 0.0
    return (tokens_in or 0) * r[0] / 1_000_000 + (tokens_out or 0) * r[1] / 1_000_000 + (searches or 0) * search_rate(model)


def known(model):
    return rate(model) is not None
