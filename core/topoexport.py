"""The topology map as a diagram other programs open: draw.io (diagrams.net, a .drawio XML file) and Visio (.vsdx, a zip of XML parts).
Both take the same picture: `tiles` (one per device: id, label, sub, x, y, w, h in pixels with the top-left corner, colour) and `links`
(a, b: tile ids; label_a, label_b: the port at each end; colour; dashed; width). Nothing here touches the window."""
import io
import math
import zipfile
from xml.sax.saxutils import escape, quoteattr

PX_PER_INCH = 96                     # the map's pixels -> Visio's inches
MARGIN = 0.75                        # inches round the drawing on the Visio page


def _attr(v):
    return quoteattr(str(v))


# =============================================================================== draw.io
def drawio_xml(name, tiles, links):
    """A .drawio file: one diagram, rounded boxes in the role colours, lines with a port label at each end."""
    cells = ['<mxCell id="0"/>', '<mxCell id="1" parent="0"/>']
    ids = {}
    for i, t in enumerate(tiles):
        cid = f"n{i + 1}"
        ids[t["id"]] = cid
        html = lambda s: str(s).replace("<", "&lt;").replace(">", "&gt;")      # the value is HTML to draw.io (html=1); a bare & is fine there
        label = html(t["label"]) + (f"<br><font style=\"font-size: 9px\">{html(t['sub'])}</font>" if t.get("sub") else "")
        style = (f"rounded=1;whiteSpace=wrap;html=1;fillColor={t.get('colour', '#78838A')};strokeColor=none;fontColor=#FFFFFF;"
                 "fontStyle=1;arcSize=20;")
        cells.append(f'<mxCell id="{cid}" value={_attr(label)} style={_attr(style)} vertex="1" parent="1">'
                     f'<mxGeometry x="{t["x"]:.1f}" y="{t["y"]:.1f}" width="{t["w"]:.1f}" height="{t["h"]:.1f}" as="geometry"/></mxCell>')
    for i, l in enumerate(links):
        a, b = ids.get(l["a"]), ids.get(l["b"])
        if not a or not b:
            continue
        eid = f"e{i + 1}"
        style = (f"endArrow=none;html=1;strokeColor={l.get('colour', '#8d9ea8')};strokeWidth={l.get('width', 2)};"
                 + ("dashed=1;" if l.get("dashed") else "") + "edgeStyle=none;")
        cells.append(f'<mxCell id="{eid}" style={_attr(style)} edge="1" parent="1" source="{a}" target="{b}">'
                     '<mxGeometry relative="1" as="geometry"/></mxCell>')
        for side, pos in (("label_a", -0.72), ("label_b", 0.72)):
            if l.get(side):
                cells.append(f'<mxCell id="{eid}{side[-1]}" value={_attr(l[side])} '
                             'style="edgeLabel;html=1;align=center;verticalAlign=middle;resizable=0;fontSize=9;fontFamily=Consolas;" '
                             f'vertex="1" connectable="0" parent="{eid}"><mxGeometry x="{pos}" relative="1" as="geometry"/></mxCell>')
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<mxfile host="Toner" type="device"><diagram name={_attr(name)} id="toner-{name.lower().replace(" ", "-")}">'
            '<mxGraphModel dx="0" dy="0" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" '
            'pageScale="1" pageWidth="1169" pageHeight="827" math="0" shadow="0"><root>' + "".join(cells) +
            '</root></mxGraphModel></diagram></mxfile>\n')


# =============================================================================== Visio
NS = "http://schemas.microsoft.com/office/visio/2012/main"
NS_R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
CT = {
    "document": "application/vnd.ms-visio.drawing.main+xml",
    "pages": "application/vnd.ms-visio.pages+xml",
    "page": "application/vnd.ms-visio.page+xml",
}
REL = {
    "document": "http://schemas.microsoft.com/visio/2010/relationships/document",
    "pages": "http://schemas.microsoft.com/visio/2010/relationships/pages",
    "page": "http://schemas.microsoft.com/visio/2010/relationships/page",
}


def _cell(n, v, f=None):
    return f'<Cell N="{n}" V={_attr(v)}' + (f' F={_attr(f)}' if f else "") + "/>"


def _box_shape(sid, t, page_h):
    """A rounded box: Visio measures from the bottom-left corner, in inches, so y is flipped."""
    w, h = t["w"] / PX_PER_INCH, t["h"] / PX_PER_INCH
    x = MARGIN + t["x"] / PX_PER_INCH
    y = page_h - MARGIN - t["y"] / PX_PER_INCH - h
    text = t["label"] + (f"\n{t['sub']}" if t.get("sub") else "")
    colour = t.get("colour", "#78838A")
    return (f'<Shape ID="{sid}" NameU="Device.{sid}" Name="Device.{sid}" Type="Shape" LineStyle="0" FillStyle="0" TextStyle="0">'
            + _cell("PinX", f"{x + w / 2:.4f}") + _cell("PinY", f"{y + h / 2:.4f}") + _cell("Width", f"{w:.4f}") + _cell("Height", f"{h:.4f}")
            + _cell("LocPinX", f"{w / 2:.4f}", "Width*0.5") + _cell("LocPinY", f"{h / 2:.4f}", "Height*0.5")
            + _cell("Angle", "0") + _cell("FlipX", "0") + _cell("FlipY", "0") + _cell("ResizeMode", "0")
            + _cell("FillForegnd", colour) + _cell("FillBkgnd", colour) + _cell("LineColor", colour) + _cell("LineWeight", "0.01")
            + _cell("Rounding", "0.08") + _cell("VerticalAlign", "1")
            + '<Section N="Character"><Row IX="0">' + _cell("Font", "Segoe UI") + _cell("Color", "#FFFFFF") + _cell("Size", "0.1111")
            + _cell("Style", "1") + "</Row></Section>"
            + '<Section N="Paragraph"><Row IX="0">' + _cell("HorzAlign", "1") + "</Row></Section>"
            + '<Section N="Geometry" IX="0">' + _cell("NoFill", "0") + _cell("NoLine", "0")
            + '<Row T="RelMoveTo" IX="1">' + _cell("X", "0") + _cell("Y", "0") + "</Row>"
            + '<Row T="RelLineTo" IX="2">' + _cell("X", "1") + _cell("Y", "0") + "</Row>"
            + '<Row T="RelLineTo" IX="3">' + _cell("X", "1") + _cell("Y", "1") + "</Row>"
            + '<Row T="RelLineTo" IX="4">' + _cell("X", "0") + _cell("Y", "1") + "</Row>"
            + '<Row T="RelLineTo" IX="5">' + _cell("X", "0") + _cell("Y", "0") + "</Row></Section>"
            + f"<Text>{escape(text)}</Text></Shape>")


def _line_shape(sid, l, a, b, page_h):
    """A one-dimensional connector between the centres of two boxes, its port labels as the text."""
    def centre(t):
        return MARGIN + (t["x"] + t["w"] / 2) / PX_PER_INCH, page_h - MARGIN - (t["y"] + t["h"] / 2) / PX_PER_INCH
    (x1, y1), (x2, y2) = centre(a), centre(b)
    dx, dy = x2 - x1, y2 - y1
    length = math.hypot(dx, dy) or 0.001
    angle = math.atan2(dy, dx)
    text = "  —  ".join(x for x in (l.get("label_a"), l.get("label_b")) if x)
    colour = l.get("colour", "#8d9ea8")
    return (f'<Shape ID="{sid}" NameU="Link.{sid}" Name="Link.{sid}" Type="Shape" LineStyle="0" FillStyle="0" TextStyle="0">'
            + _cell("BeginX", f"{x1:.4f}") + _cell("BeginY", f"{y1:.4f}") + _cell("EndX", f"{x2:.4f}") + _cell("EndY", f"{y2:.4f}")
            + _cell("PinX", f"{x1:.4f}", "BeginX") + _cell("PinY", f"{y1:.4f}", "BeginY") + _cell("Width", f"{length:.4f}", "SQRT((EndX-BeginX)^2+(EndY-BeginY)^2)")
            + _cell("Height", "0") + _cell("LocPinX", "0") + _cell("LocPinY", "0") + _cell("Angle", f"{angle:.6f}", "ATAN2(EndY-BeginY,EndX-BeginX)")
            + _cell("ObjType", "2") + _cell("LineColor", colour) + _cell("LineWeight", f"{0.01 * l.get('width', 2):.3f}")
            + _cell("LinePattern", "9" if l.get("dashed") else "1") + _cell("BeginArrow", "0") + _cell("EndArrow", "0")
            + _cell("TxtPinX", f"{length / 2:.4f}", "Width*0.5") + _cell("TxtPinY", "0.12") + _cell("TxtWidth", f"{max(length, 1.2):.4f}") + _cell("TxtHeight", "0.2")
            + '<Section N="Character"><Row IX="0">' + _cell("Font", "Consolas") + _cell("Color", colour) + _cell("Size", "0.0972") + "</Row></Section>"
            + '<Section N="Geometry" IX="0">' + _cell("NoFill", "1") + _cell("NoLine", "0")
            + '<Row T="MoveTo" IX="1">' + _cell("X", "0") + _cell("Y", "0") + "</Row>"
            + '<Row T="LineTo" IX="2">' + _cell("X", f"{length:.4f}", "Width") + _cell("Y", "0") + "</Row></Section>"
            + (f"<Text>{escape(text)}</Text>" if text else "") + "</Shape>")


def vsdx_bytes(name, tiles, links):
    """A .vsdx file: the OPC package with one page holding the boxes and the connectors glued to them."""
    width_px = max((t["x"] + t["w"] for t in tiles), default=800)
    height_px = max((t["y"] + t["h"] for t in tiles), default=600)
    page_w = width_px / PX_PER_INCH + 2 * MARGIN
    page_h = height_px / PX_PER_INCH + 2 * MARGIN
    ids = {}
    shapes, connects = [], []
    for i, t in enumerate(tiles):
        ids[t["id"]] = i + 1
        shapes.append(_box_shape(i + 1, t, page_h))
    by_id = {t["id"]: t for t in tiles}
    sid = len(tiles) + 1
    for l in links:
        a, b = by_id.get(l["a"]), by_id.get(l["b"])
        if not a or not b:
            continue
        shapes.append(_line_shape(sid, l, a, b, page_h))
        connects.append(f'<Connect FromSheet="{sid}" FromCell="BeginX" FromPart="9" ToSheet="{ids[l["a"]]}" ToCell="PinX" ToPart="3"/>'
                        f'<Connect FromSheet="{sid}" FromCell="EndX" FromPart="12" ToSheet="{ids[l["b"]]}" ToCell="PinX" ToPart="3"/>')
        sid += 1
    page_xml = (f'<?xml version="1.0" encoding="utf-8"?>\n<PageContents xmlns="{NS}" xmlns:r="{NS_R}" xml:space="preserve">'
                "<Shapes>" + "".join(shapes) + "</Shapes>" + ("<Connects>" + "".join(connects) + "</Connects>" if connects else "")
                + "</PageContents>")
    pages_xml = (f'<?xml version="1.0" encoding="utf-8"?>\n<Pages xmlns="{NS}" xmlns:r="{NS_R}" xml:space="preserve">'
                 f'<Page ID="0" NameU="Page-1" Name={_attr(name)} ViewScale="1" ViewCenterX="{page_w / 2:.3f}" ViewCenterY="{page_h / 2:.3f}">'
                 '<PageSheet LineStyle="0" FillStyle="0" TextStyle="0">'
                 + _cell("PageWidth", f"{page_w:.4f}") + _cell("PageHeight", f"{page_h:.4f}") + _cell("PageScale", "1", None) + _cell("DrawingScale", "1")
                 + _cell("DrawingSizeType", "3") + _cell("DrawingScaleType", "0") + _cell("InhibitSnap", "0")
                 + '</PageSheet><Rel r:id="rId1"/></Page></Pages>')
    document_xml = (f'<?xml version="1.0" encoding="utf-8"?>\n<VisioDocument xmlns="{NS}" xmlns:r="{NS_R}" xml:space="preserve">'
                    '<DocumentSettings TopPage="0" DefaultTextStyle="0" DefaultLineStyle="0" DefaultFillStyle="0" DefaultGuideStyle="0"/>'
                    '<StyleSheets><StyleSheet ID="0" NameU="No Style" Name="No Style">'
                    + _cell("EnableLineProps", "1") + _cell("EnableFillProps", "1") + _cell("EnableTextProps", "1")
                    + _cell("LineWeight", "0.01") + _cell("LineColor", "#000000") + _cell("LinePattern", "1")
                    + _cell("FillForegnd", "#FFFFFF") + _cell("FillBkgnd", "#FFFFFF") + _cell("FillPattern", "1")
                    + _cell("TextBkgnd", "0") + _cell("VerticalAlign", "1")
                    + '<Section N="Character"><Row IX="0">' + _cell("Font", "Calibri") + _cell("Color", "#000000") + _cell("Size", "0.1667") + "</Row></Section>"
                    + '<Section N="Paragraph"><Row IX="0">' + _cell("HorzAlign", "1") + "</Row></Section>"
                    + "</StyleSheet></StyleSheets></VisioDocument>")
    content_types = ('<?xml version="1.0" encoding="utf-8"?>\n<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                     '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                     '<Default Extension="xml" ContentType="application/xml"/>'
                     f'<Override PartName="/visio/document.xml" ContentType="{CT["document"]}"/>'
                     f'<Override PartName="/visio/pages/pages.xml" ContentType="{CT["pages"]}"/>'
                     f'<Override PartName="/visio/pages/page1.xml" ContentType="{CT["page"]}"/>'
                     '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
                     '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>'
                     "</Types>")
    rels = ('<?xml version="1.0" encoding="utf-8"?>\n<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            f'<Relationship Id="rId1" Type="{REL["document"]}" Target="visio/document.xml"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
            '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>'
            "</Relationships>")
    doc_rels = ('<?xml version="1.0" encoding="utf-8"?>\n<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                f'<Relationship Id="rId1" Type="{REL["pages"]}" Target="pages/pages.xml"/></Relationships>')
    pages_rels = ('<?xml version="1.0" encoding="utf-8"?>\n<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                  f'<Relationship Id="rId1" Type="{REL["page"]}" Target="page1.xml"/></Relationships>')
    core = ('<?xml version="1.0" encoding="utf-8"?>\n<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            f"<dc:title>{escape(name)}</dc:title><dc:creator>Toner</dc:creator></cp:coreProperties>")
    app = ('<?xml version="1.0" encoding="utf-8"?>\n<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
           "<Application>Toner</Application></Properties>")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("_rels/.rels", rels)
        z.writestr("docProps/core.xml", core)
        z.writestr("docProps/app.xml", app)
        z.writestr("visio/document.xml", document_xml)
        z.writestr("visio/_rels/document.xml.rels", doc_rels)
        z.writestr("visio/pages/pages.xml", pages_xml)
        z.writestr("visio/pages/_rels/pages.xml.rels", pages_rels)
        z.writestr("visio/pages/page1.xml", page_xml)
    return buf.getvalue()
