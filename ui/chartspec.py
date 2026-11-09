"""The charts Toner draws with ECharts, as plain dictionaries: what to show, in Toner's colours, with nothing of Qt in it.

Each builder returns the option an ECharts chart takes (see ui/webchart.py, which puts it on a page). They share one look: the
theme's text and muted colours, no chart background (the panel behind shows through), a tooltip, and the status colours
Toner uses everywhere (Settings > Appearance > Status colours), so a FAIL is the same red on a pill, in a table and on a chart.
Being plain data, every builder is tested without a window (tests/test_chartspec.py)."""
from datetime import datetime

STATUSES = ("OK", "WARN", "FAIL", "ERROR", "N/A")
EMPTY = "__empty"                       # an option that is only this key tells the page to show the text instead of a chart

# Series colours for things that are not statuses: distinct in both light and dark themes, colour-blind friendly order.
SERIES = ["#2563eb", "#f59e0b", "#10b981", "#8b5cf6", "#ec4899", "#14b8a6", "#f97316", "#64748b", "#84cc16", "#06b6d4"]


def palette(tokens=None, status_colors=None):
    """The colours a chart is drawn in, from the theme's tokens (ui.theme.current()) and the status colours (ui.status.ink).
    Both default to a light theme, so a chart can be built with no window at all."""
    t = tokens or {}
    st = status_colors or {}
    return {"text": t.get("text", "#1f2937"), "muted": t.get("muted", "#6b7280"), "border": t.get("border", "#d1d5db"),
            "surface": t.get("surface", "#ffffff"), "accent": t.get("accent", "#2563eb"), "dark": bool(t.get("dark")),
            "status": {"OK": st.get("OK", "#16a34a"), "WARN": st.get("WARN", "#d97706"), "FAIL": st.get("FAIL", "#dc2626"),
                       "ERROR": st.get("ERROR", "#7c3aed"), "N/A": st.get("N/A", "#9e9e9e")},
            "series": list(SERIES)}


def empty(text):
    """No chart: the page shows `text` in the middle instead."""
    return {EMPTY: text}


# ---------------------------------------------------------------- shared pieces
def _font(p, size=12, color=None):
    return {"fontFamily": 'system-ui, "Segoe UI", sans-serif', "fontSize": size, "color": color or p["text"]}


def _tooltip(p, trigger="item", formatter=None):
    tip = {"trigger": trigger, "backgroundColor": p["surface"], "borderColor": p["border"], "borderWidth": 1,
           "textStyle": _font(p, 12), "confine": True, "appendToBody": False}
    if trigger == "axis":
        tip["axisPointer"] = {"type": "shadow", "shadowStyle": {"opacity": 0.08}}
    if formatter:
        tip["formatter"] = formatter
    return tip


def _axis(p, kind, data=None, name="", fmt=None, boundary_gap=None):
    ax = {"type": kind, "axisLine": {"lineStyle": {"color": p["border"]}}, "axisTick": {"show": False},
          "axisLabel": {**_font(p, 11, p["muted"]), "hideOverlap": True}, "splitLine": {"lineStyle": {"color": p["border"], "opacity": 0.5}},
          "nameTextStyle": _font(p, 11, p["muted"])}
    if data is not None:
        ax["data"] = list(data)
    if name:
        ax["name"] = name
    if fmt:
        ax["axisLabel"]["formatter"] = fmt
    if boundary_gap is not None:
        ax["boundaryGap"] = boundary_gap
    if kind == "category":
        ax["splitLine"] = {"show": False}
    return ax


def _legend(p, show=True, top=0):
    return {"show": show, "top": top, "left": "center", "icon": "circle", "itemWidth": 10, "itemHeight": 10,
            "textStyle": _font(p, 11, p["muted"])}


def _title(p, text, sub=""):
    if not text:
        return {"show": False}
    t = {"text": text, "left": 0, "top": 0, "textStyle": _font(p, 13), "subtextStyle": _font(p, 11, p["muted"])}
    if sub:
        t["subtext"] = sub
    return t


def _base(p, title="", sub="", legend=False, grid=None, animate=True):
    opt = {"backgroundColor": "transparent", "textStyle": _font(p), "title": _title(p, title, sub),
           "legend": _legend(p, legend, top=22 if title else 0), "animation": animate, "animationDuration": 350,
           "color": p["series"]}
    g = {"left": 8, "right": 12, "top": (48 if title else 8) + (22 if legend else 0), "bottom": 8, "containLabel": True}
    if grid:
        g.update(grid)
    opt["grid"] = g
    return opt


def status_color(p, status):
    return p["status"].get(status, p["status"]["N/A"])


# ---------------------------------------------------------------- the charts
def donut(p, counts, title="", center_text=None, order=STATUSES):
    """Devices (or checks) by status as a ring: counts is {status: n}. The middle shows `center_text` (the total by default).
    A click reports the status in `name`."""
    total = sum(counts.values())
    if not total:
        return empty("Nothing to show yet")
    data = [{"name": s, "value": counts[s], "itemStyle": {"color": status_color(p, s)}} for s in order if counts.get(s)]
    data += [{"name": s, "value": n, "itemStyle": {"color": status_color(p, s)}} for s, n in counts.items() if s not in order and n]
    opt = _base(p, title, legend=True)
    opt["tooltip"] = _tooltip(p, formatter="{b}: {c} ({d}%)")
    opt["series"] = [{"type": "pie", "radius": ["58%", "82%"], "center": ["50%", "56%"], "avoidLabelOverlap": True,
                      "itemStyle": {"borderColor": p["surface"], "borderWidth": 2, "borderRadius": 4},
                      "label": {"show": False}, "emphasis": {"scale": True, "scaleSize": 4, "label": {"show": False}},
                      "data": data}]
    opt["graphic"] = [{"type": "text", "left": "center", "top": "50%", "style": {"text": str(center_text if center_text is not None else total),
                                                                                "fill": p["text"], "fontSize": 22, "fontWeight": "bold",
                                                                                "fontFamily": _font(p)["fontFamily"], "textAlign": "center"}}]
    return opt


def pie(p, slices, title=""):
    """Slices as a doughnut: slices is [(name, value, colour)]. Every name stays in the legend, even at zero."""
    if not any(v for _n, v, _c in slices):
        return empty("")
    opt = _base(p, title, legend=True)
    opt["tooltip"] = _tooltip(p, formatter="{b}: {c} ({d}%)")
    opt["series"] = [{"type": "pie", "radius": ["40%", "68%"], "center": ["50%", "58%"], "avoidLabelOverlap": True,
                      "itemStyle": {"borderColor": p["surface"], "borderWidth": 2, "borderRadius": 4},
                      "label": {"show": False}, "emphasis": {"scale": True, "scaleSize": 4, "label": {"show": False}},
                      "data": [{"name": n, "value": v, "itemStyle": {"color": c}} for n, v, c in slices]}]
    return opt


def bars(p, categories, values, title="", unit="", horizontal=False, colors=None, limit=None, warn=None, fail=None, extra=None):
    """One value per category. `colors`: one per bar (else the accent); `warn`/`fail`: a bar at or past them takes the status
    colour, `limit`: a dashed line at that value. `extra`: one object per bar sent back on click (a device key, say)."""
    if not categories:
        return empty("Nothing to show yet")
    data = []
    for i, (c, v) in enumerate(zip(categories, values)):
        col = (colors[i] if colors and i < len(colors) else None)
        if col is None and (warn is not None or fail is not None) and v is not None:
            col = status_color(p, "FAIL") if fail is not None and v >= fail else status_color(p, "WARN") if warn is not None and v >= warn else status_color(p, "OK")
        item = {"value": v, "itemStyle": {"color": col or p["accent"], "borderRadius": 3}}
        if extra and i < len(extra):
            item["extra"] = extra[i]
        data.append(item)
    opt = _base(p, title, grid={"left": 4} if not horizontal else {"left": 4, "right": 36})
    opt["tooltip"] = _tooltip(p, "axis", formatter=("{b}: {c}" + unit))
    cat, val = _axis(p, "category", categories), _axis(p, "value", fmt=("{value}" + unit) if unit else None)
    if horizontal:
        cat["inverse"] = True
        opt["xAxis"], opt["yAxis"] = val, cat
    else:
        cat["axisLabel"]["interval"] = 0
        cat["axisLabel"]["rotate"] = 30 if len(categories) > 8 else 0
        opt["xAxis"], opt["yAxis"] = cat, val
    series = {"type": "bar", "data": data, "barMaxWidth": 28, "label": {"show": horizontal, "position": "right", **_font(p, 11, p["muted"]),
                                                                          "formatter": "{c}" + unit}}
    if limit is not None:
        series["markLine"] = {"symbol": "none", "silent": True, "lineStyle": {"color": p["muted"], "type": "dashed"},
                              "label": {"show": False}, "data": [{"xAxis": limit} if horizontal else {"yAxis": limit}]}
    opt["series"] = [series]
    return opt


def grouped_bars(p, categories, series, title="", unit="", stacked=False, colors=None, percent=False):
    """Several series over the same categories: series is [(name, [values...]), ...]. Stacked when asked; `colors` by series
    name (a status name picks its status colour by itself)."""
    if not categories or not series:
        return empty("Nothing to show yet")
    opt = _base(p, title, legend=True)
    opt["tooltip"] = _tooltip(p, "axis")
    cat, val = _axis(p, "category", categories), _axis(p, "value", fmt=("{value}" + unit) if unit else None)
    cat["axisLabel"]["interval"] = 0
    cat["axisLabel"]["rotate"] = 30 if len(categories) > 8 else 0
    if percent:
        val["max"] = 100
    opt["xAxis"], opt["yAxis"] = cat, val
    out = []
    for i, (name, vals) in enumerate(series):
        col = (colors or {}).get(name) or (p["status"].get(name) if name in p["status"] else p["series"][i % len(p["series"])])
        s = {"type": "bar", "name": name, "data": list(vals), "itemStyle": {"color": col, "borderRadius": 2 if not stacked else 0},
             "barMaxWidth": 32, "emphasis": {"focus": "series"}}
        if stacked:
            s["stack"] = "total"
        out.append(s)
    opt["series"] = out
    return opt


def heatmap(p, xlabels, ylabels, cells, title="", unit="", worst=None):
    """A grid of values: cells is [(xi, yi, value), ...]. Colour runs from the surface to the FAIL colour (or to `worst`)."""
    if not cells:
        return empty("Nothing to show yet")
    top = max((c[2] for c in cells), default=0) or 1
    opt = _base(p, title, grid={"right": 70, "bottom": 10})
    opt["tooltip"] = _tooltip(p, formatter="{b}: {c}" if not unit else "{c}" + unit)
    x, y = _axis(p, "category", xlabels), _axis(p, "category", ylabels)
    x["splitArea"] = y["splitArea"] = {"show": False}
    y["inverse"] = True
    opt["xAxis"], opt["yAxis"] = x, y
    opt["visualMap"] = {"min": 0, "max": top, "calculable": False, "orient": "vertical", "right": 0, "top": "center",
                        "itemHeight": 100, "textStyle": _font(p, 10, p["muted"]),
                        "inRange": {"color": [p["surface"] if not p["dark"] else "#2a2f3a", worst or status_color(p, "FAIL")]}}
    opt["series"] = [{"type": "heatmap", "data": [[xi, yi, v] for xi, yi, v in cells], "label": {"show": top <= 30, **_font(p, 10)},
                      "itemStyle": {"borderColor": p["surface"], "borderWidth": 1},
                      "emphasis": {"itemStyle": {"shadowBlur": 6, "shadowColor": "rgba(0,0,0,0.25)"}}}]
    return opt


def status_heatmap(p, xlabels, ylabels, cells, title=""):
    """A grid coloured by status: cells is [(xi, yi, status)], ERROR as red as FAIL. Blank squares are not sent. A click reports
    value: [x, y, n]. The third
    value is a number (the status's place in STATUSES) because ECharts skips heatmap squares whose value is not one; the tooltip names it."""
    if not cells:
        return empty("Nothing to show yet")
    opt = _base(p, title)
    opt["tooltip"] = _tooltip(p, formatter="{b}")
    x, y = _axis(p, "category", xlabels), _axis(p, "category", ylabels)
    x["splitArea"] = y["splitArea"] = {"show": False}
    y["inverse"] = True
    opt["xAxis"], opt["yAxis"] = x, y
    opt["series"] = [{"type": "heatmap", "data": [{"name": s, "value": [xi, yi, STATUSES.index(s) if s in STATUSES else len(STATUSES)],
                                "itemStyle": {"color": status_color(p, "FAIL" if s == "ERROR" else s)}} for xi, yi, s in cells],
                      "itemStyle": {"borderColor": p["surface"], "borderWidth": 1},
                      "emphasis": {"itemStyle": {"shadowBlur": 6, "shadowColor": "rgba(0,0,0,0.25)"}}}]
    return opt


def ring(p, segments, center_text, title=""):
    """Segments as a ring: segments is [(name, value, colour)]. `center_text` sits in the middle; a click reports the name. With every
    segment at zero the ring is a plain grey circle that cannot be selected, still with its centre text."""
    opt = pie(p, segments, title)
    if not opt.get("series"):
        opt = pie(p, [("", 1, p["border"])], title)
        opt["legend"]["show"] = False
        opt["tooltip"] = {"show": False}
        opt["series"][0]["silent"] = True
    opt["series"][0]["radius"] = ["58%", "82%"]
    opt["series"][0]["center"] = ["50%", "56%"]
    opt["graphic"] = [{"type": "text", "left": "center", "top": "50%", "style": {"text": str(center_text), "fill": p["text"], "fontSize": 22,
                                                                              "fontWeight": "bold", "fontFamily": _font(p)["fontFamily"],
                                                                              "textAlign": "center"}}]
    return opt


def gauge(p, value, warn=None, fail=None, title="", unit="%", maximum=100, lower_is_worse=False):
    """One reading against its limits: a half ring, coloured by the band the value is in. `lower_is_worse` for uptime-like readings."""
    if value is None:
        return empty("No reading yet")
    ok, wa, fa = status_color(p, "OK"), status_color(p, "WARN"), status_color(p, "FAIL")
    mx = float(maximum) or 100.0
    stops = []
    if warn is None and fail is None:
        stops = [[1, p["accent"]]]
    elif lower_is_worse:
        for lim, col in ((fail, fa), (warn, wa)):
            if lim is not None:
                stops.append([min(1.0, max(0.0, lim / mx)), col])
        stops.append([1, ok])
    else:
        for lim, col in ((warn, ok), (fail, wa)):
            if lim is not None:
                stops.append([min(1.0, max(0.0, lim / mx)), col])
        stops.append([1, fa])
    stops = sorted(stops, key=lambda s: s[0])
    opt = _base(p, "", animate=True)
    opt["grid"] = {"show": False}
    opt["series"] = [{"type": "gauge", "startAngle": 200, "endAngle": -20, "min": 0, "max": mx, "radius": "100%", "center": ["50%", "62%"],
                      "progress": {"show": False},
                      "axisLine": {"lineStyle": {"width": 14, "color": stops}},
                      "pointer": {"width": 4, "length": "55%", "offsetCenter": [0, 0], "itemStyle": {"color": p["text"]}},
                      "anchor": {"show": True, "size": 10, "offsetCenter": [0, 0], "itemStyle": {"color": p["text"]}},
                      "axisTick": {"show": False}, "splitLine": {"show": False},
                      "axisLabel": {"show": False},
                      "title": {"show": bool(title), "offsetCenter": [0, "66%"], **_font(p, 12, p["muted"])},
                      "detail": {"valueAnimation": True, "offsetCenter": [0, "34%"], "formatter": "{value}" + unit, **_font(p, 20), "fontWeight": "bold"},
                      "data": [{"value": round(float(value), 1), "name": title}]}]
    return opt


def area(p, times, series, title="", unit="", warn=None, fail=None, stacked=False, smooth=True):
    """Values over time: times is a list of datetimes or epoch seconds, series [(name, [values...]), ...]. Dashed lines mark the
    limits. Hover shows every series at that moment."""
    if not times or not series:
        return empty("Nothing to show yet")
    ts = [(t.timestamp() if isinstance(t, datetime) else float(t)) * 1000 for t in times]
    opt = _base(p, title, legend=len(series) > 1, grid={"right": 48 if (warn is not None or fail is not None) else 12})
    opt["tooltip"] = _tooltip(p, "axis")
    opt["tooltip"]["axisPointer"] = {"type": "line", "lineStyle": {"color": p["muted"]}}
    opt["xAxis"] = _axis(p, "time")
    opt["xAxis"]["axisLabel"]["formatter"] = {"year": "{yyyy}", "month": "{MMM}", "day": "{d} {MMM}", "hour": "{HH}:{mm}", "minute": "{HH}:{mm}",
                                              "second": "{HH}:{mm}:{ss}", "millisecond": "{HH}:{mm}"}
    opt["xAxis"]["splitLine"] = {"show": False}
    opt["yAxis"] = _axis(p, "value", fmt=("{value}" + unit) if unit else None)
    out = []
    for i, (name, vals) in enumerate(series):
        col = p["status"].get(name) if name in p["status"] else p["series"][i % len(p["series"])]
        s = {"type": "line", "name": name, "smooth": smooth, "showSymbol": False, "connectNulls": False,
             "data": [[t, v] for t, v in zip(ts, vals)], "lineStyle": {"width": 2, "color": col}, "itemStyle": {"color": col},
             "areaStyle": {"opacity": 0.12, "color": col}, "emphasis": {"focus": "series"}}
        if stacked:
            s["stack"] = "total"
        out.append(s)
    marks = [{"yAxis": v, "lineStyle": {"color": status_color(p, st), "type": "dashed"},
              "label": {"formatter": st, "position": "end", **_font(p, 10, status_color(p, st))}}
             for v, st in ((warn, "WARN"), (fail, "FAIL")) if v is not None]
    if marks and out:
        out[0]["markLine"] = {"symbol": "none", "silent": True, "data": marks}
    opt["series"] = out
    return opt


def sparkline(p, values, color=None):
    """A small bare line for a tile: no axes, no tooltip."""
    if not values:
        return empty("")
    return {"backgroundColor": "transparent", "animation": False, "grid": {"left": 0, "right": 0, "top": 2, "bottom": 2},
            "xAxis": {"type": "category", "show": False, "data": list(range(len(values)))},
            "yAxis": {"type": "value", "show": False, "min": "dataMin", "max": "dataMax"},
            "series": [{"type": "line", "data": list(values), "smooth": True, "showSymbol": False,
                        "lineStyle": {"width": 1.5, "color": color or p["accent"]}, "areaStyle": {"opacity": 0.15, "color": color or p["accent"]}}]}
