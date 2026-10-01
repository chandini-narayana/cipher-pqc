#!/usr/bin/env python3
"""
Diagram generator for the CIPHER Raspberry Pi Hardware Assembly Manual.

Generates every vector diagram used by manual.html into ../diagrams/*.svg.
Kept as an editable source file per the manual's "docs/hardware_manual/"
source-material requirement -- re-run this script after changing colors,
labels, or layout instead of hand-editing the generated SVGs.

Usage:
    python gen_diagrams.py
"""
from __future__ import annotations
import html
import os

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "diagrams")
os.makedirs(OUT_DIR, exist_ok=True)

# ---------------------------------------------------------------- palette --
NAVY = "#0a1628"
NAVY2 = "#123055"
CYAN = "#22d3ee"
CYAND = "#0891b2"
WHITE = "#ffffff"
GREY = "#64748b"
GREYL = "#cbd5e1"
GREYBG = "#f1f5f9"
GREEN = "#16a34a"
GREENBG = "#dcfce7"
AMBER = "#d97706"
AMBERBG = "#fef3c7"
ORANGE = "#ea580c"
ORANGEBG = "#ffedd5"
RED = "#dc2626"
REDBG = "#fee2e2"

STATUS = {
    "impl": (GREEN, GREENBG, "CURRENTLY IMPLEMENTED"),
    "hw": (AMBER, AMBERBG, "HARDWARE INTEGRATION PENDING"),
    "sw": (ORANGE, ORANGEBG, "SOFTWARE IMPLEMENTATION PENDING"),
    "gpio": (RED, REDBG, "GPIO ASSIGNMENT PENDING"),
    "info": (CYAND, "#e0f2fe", "REFERENCE"),
}


def esc(s: str) -> str:
    return html.escape(str(s), quote=True)


class SVG:
    def __init__(self, w, h):
        self.w, self.h = w, h
        self.parts = []
        self.defs = []
        self._marker("arrow", NAVY)
        self._marker("arrowc", CYAND)
        self._marker("arrowg", GREY)

    def _marker(self, mid, color):
        self.defs.append(
            f'<marker id="{mid}" viewBox="0 0 10 10" refX="8" refY="5" '
            f'markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
            f'<path d="M0,0 L10,5 L0,10 z" fill="{color}"/></marker>'
        )

    def raw(self, s):
        self.parts.append(s)

    def rect(self, x, y, w, h, fill=WHITE, stroke=NAVY, sw=2, rx=10, dash=None):
        d = f' stroke-dasharray="{dash}"' if dash else ""
        self.parts.append(
            f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" ry="{rx}" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="{sw}"{d}/>'
        )

    def circle(self, cx, cy, r, fill=WHITE, stroke=NAVY, sw=2):
        self.parts.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"/>'
        )

    def line(self, x1, y1, x2, y2, color=NAVY, sw=3, marker="arrow", dash=None):
        d = f' stroke-dasharray="{dash}"' if dash else ""
        m = f' marker-end="url(#{marker})"' if marker else ""
        self.parts.append(
            f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" '
            f'stroke-width="{sw}" stroke-linecap="round"{d}{m}/>'
        )

    def text(self, x, y, s, size=14, weight=600, fill=NAVY, anchor="start",
              family="Segoe UI, Arial, sans-serif", spacing=None, style="normal"):
        sp = f' letter-spacing="{spacing}"' if spacing else ""
        self.parts.append(
            f'<text x="{x}" y="{y}" font-size="{size}" font-weight="{weight}" '
            f'font-style="{style}" fill="{fill}" text-anchor="{anchor}" font-family="{family}"{sp}>{esc(s)}</text>'
        )

    def mtext(self, x, y, lines, size=12.5, weight=500, fill="#334155", anchor="start", lh=None, family="Segoe UI, Arial, sans-serif"):
        lh = lh or size * 1.45
        for i, ln in enumerate(lines):
            self.text(x, y + i * lh, ln, size=size, weight=weight, fill=fill, anchor=anchor, family=family)

    def pill(self, x, y, label, kind="impl", w=None, h=22, size=10.5):
        color, bg, _ = STATUS[kind]
        w = w or (len(label) * size * 0.86 + 40)
        self.rect(x, y, w, h, fill=bg, stroke=color, sw=1.6, rx=h / 2)
        self.circle(x + 15, y + h / 2, 3.2, fill=color, stroke="none")
        self.text(x + 25, y + h / 2 + 4, label, size=size, weight=800, fill=color, anchor="start")
        return w

    def varrow(self, x, y1, y2, color=NAVY, sw=3, marker="arrow"):
        self.line(x, y1, x, y2, color=color, sw=sw, marker=marker)

    def harrow(self, x1, x2, y, color=NAVY, sw=3, marker="arrow"):
        self.line(x1, y, x2, y, color=color, sw=sw, marker=marker)

    def box(self, x, y, w, h, title, subtitle=None, fill=WHITE, stroke=NAVY, tsize=14.5,
             ssize=11, sfill=GREY, sw=2.2, rx=10, title_weight=800, center=True):
        self.rect(x, y, w, h, fill=fill, stroke=stroke, sw=sw, rx=rx)
        anchor = "middle" if center else "start"
        tx = x + w / 2 if center else x + 14
        ty = y + (h / 2 - 6 if subtitle else h / 2 + 5)
        self.text(tx, ty, title, size=tsize, weight=title_weight, fill=stroke if stroke != WHITE else NAVY, anchor=anchor)
        if subtitle:
            self.text(tx, ty + 20, subtitle, size=ssize, weight=500, fill=sfill, anchor=anchor)

    def render(self):
        defs = "<defs>" + "".join(self.defs) + "</defs>"
        body = "".join(self.parts)
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {self.w} {self.h}" '
            f'font-family="Segoe UI, Arial, sans-serif">{defs}{body}</svg>'
        )

    def save(self, name):
        path = os.path.join(OUT_DIR, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.render())
        print("wrote", path)


# =====================================================================
# 1. SYSTEM OVERVIEW
# =====================================================================
def gen_system_overview():
    s = SVG(800, 1010)
    cx = 380
    # Windows laptop
    s.box(190, 14, 400, 68, "Windows Laptop", "SSH client + web browser", stroke=NAVY)
    s.pill(400, 8, "IMPLEMENTED", "impl", h=18, size=8.6)
    s.varrow(cx, 82, 130, color=NAVY)
    s.text(cx + 14, 112, "SSH (management) + HTTP dashboard", size=10.5, fill=GREY, weight=600)

    # Built-in wifi
    s.box(150, 132, 480, 56, "Raspberry Pi 4 — Built-in Wi-Fi", "management network interface")
    s.pill(430, 126, "IMPLEMENTED (OS-LEVEL)", "impl", h=18, size=8.2)
    s.varrow(cx, 188, 232, color=NAVY)
    s.text(cx + 14, 216, "trusted LAN / Wi-Fi (managed network)", size=10.5, fill=GREY, weight=600)

    # Pi main box
    s.rect(60, 234, 500, 470, fill="#f8fbfd", stroke=NAVY, sw=2.6, rx=14)
    s.text(310, 264, "RASPBERRY PI 4 MODEL B — 4GB", size=13.5, weight=900, fill=NAVY, anchor="middle", spacing="0.04em")
    s.pill(140, 276, "PI BRING-UP VERIFIED", "impl", h=18, size=8)

    # pipeline box
    s.rect(90, 302, 440, 190, fill=WHITE, stroke=CYAND, sw=2, rx=10)
    s.text(310, 322, "CIPHER SOFTWARE PIPELINE", size=11.5, weight=800, fill=CYAND, anchor="middle", spacing="0.03em")
    stages = [
        "Packet Capture → Metadata Extraction",
        "Protocol / TLS Fingerprinting → Shannon Entropy",
        "Device Features → QRS + Isolation Forest",
        "Risk Fusion → DeviceAssessment",
        "Enforcement Decision (raw QRS ≥ 7)",
    ]
    s.mtext(120, 344, stages, size=10.3, weight=600, fill="#334155")
    s.pill(360, 452, "IMPLEMENTED", "impl", h=17, size=8)

    # sub boxes: reports / dashboard
    s.box(90, 502, 210, 62, "Signed PDF Reports", "ML-DSA-44 (FIPS 204)", tsize=11.5, ssize=9)
    s.pill(105, 552, "IMPLEMENTED", "impl", h=15, size=7)
    s.box(320, 502, 210, 62, "REST API + Dashboard", "single Flask process", tsize=11.5, ssize=9)
    s.pill(335, 552, "IMPLEMENTED", "impl", h=15, size=7)

    # branch: OLED
    s.line(560, 340, 620, 340, color=GREY, sw=2, marker=None, dash="4,3")
    s.box(620, 306, 130, 68, "SSD1306", "I²C OLED display", fill=AMBERBG, stroke=AMBER, tsize=12, ssize=8.6)
    s.pill(626, 380, "HARDWARE PENDING", "hw", h=15, size=6.8)

    # branch: LEDs
    s.line(560, 400, 620, 400, color=GREY, sw=2, marker=None, dash="4,3")
    s.box(620, 400, 130, 84, "Status LEDs", "Green / Amber / Red", fill=AMBERBG, stroke=AMBER, tsize=12, ssize=8.6)
    s.pill(626, 490, "HARDWARE PENDING", "hw", h=15, size=6.8)

    # arrow to USB adapter
    s.varrow(cx, 704, 748, color=NAVY)
    w = s.pill(cx - 155, 712, "single external USB Wi-Fi adapter — monitor mode", "sw", h=20, size=8.8)

    s.box(150, 750, 480, 56, "External USB Wi-Fi Adapter", "monitor-mode packet capture (exactly one)")
    s.pill(150, 744, "CONNECTED IN SOFTWARE: PENDING", "sw", h=17, size=7.6)

    s.varrow(cx, 806, 850, color=NAVY)
    s.rect(150, 856, 480, 78, fill="#fff7ed", stroke=ORANGE, sw=2.4, rx=10, dash="7,5")
    s.text(cx, 886, "Observed IoT Device Traffic", size=13.5, weight=800, fill="#7c2d12", anchor="middle")
    s.text(cx, 906, "multiple devices — identities preserved (not host-normalized)", size=9.8, weight=600, fill="#9a3412", anchor="middle")
    s.pill(cx - 95, 916, "CAPTURE: SOFTWARE PENDING", "sw", h=16, size=7.6)

    s.save("system-overview.svg")


# =====================================================================
# 2. NETWORK ARCHITECTURE
# =====================================================================
def gen_network_architecture():
    s = SVG(760, 900)
    s.rect(40, 30, 680, 780, fill="none", stroke=GREYL, sw=2, rx=16, dash="6,5")
    s.text(380, 66, "TRUSTED NETWORK", size=13, weight=800, fill=GREY, anchor="middle", spacing="0.12em")

    s.box(120, 96, 300, 58, "Raspberry Pi 4 — Built-in Wi-Fi", "management link")
    cx1 = 270
    s.varrow(cx1, 154, 210, color=NAVY)

    # branch down to laptop and Pi
    s.line(cx1, 210, cx1, 240, color=NAVY, sw=3, marker=None)
    s.line(150, 240, 610, 240, color=NAVY, sw=3, marker=None)
    s.varrow(150, 240, 292, color=NAVY)
    s.varrow(610, 240, 292, color=NAVY)

    s.box(40, 296, 300, 74, "Windows Laptop", "SSH • web browser • dashboard client")
    s.pill(55, 356, "IMPLEMENTED", "impl", h=16, size=7.6)
    s.box(460, 296, 260, 74, "Raspberry Pi 4", "runs CIPHER software")
    s.pill(475, 356, "PI BRING-UP VERIFIED", "impl", h=16, size=7.2)

    s.varrow(590, 370, 420, color=NAVY)
    s.text(608, 400, "runs", size=10.5, fill=GREY, weight=600)

    s.rect(400, 424, 320, 130, fill="#f8fbfd", stroke=CYAND, sw=2.2, rx=12)
    s.text(560, 448, "CIPHER SOFTWARE", size=12, weight=800, fill=CYAND, anchor="middle", spacing="0.04em")
    s.mtext(422, 470, [
        "Existing pipeline (unchanged):",
        "Capture → Fingerprint → Entropy",
        "→ QRS + Isolation Forest → Fusion",
        "→ Enforcement → Reports / Dashboard",
    ], size=9.6, weight=600, fill="#334155")
    s.pill(422, 528, "IMPLEMENTED", "impl", h=15, size=7.2)

    s.varrow(560, 554, 606, color=NAVY)
    s.pill(560 - 150, 610, "exactly ONE external USB Wi-Fi adapter", "sw", h=19, size=8.6)

    s.box(400, 646, 320, 60, "External USB Wi-Fi Adapter", "monitor mode")
    s.pill(410, 640, "SOFTWARE PENDING", "sw", h=16, size=7.2)

    s.varrow(560, 706, 748, color=NAVY)
    s.rect(400, 754, 320, 44, fill=ORANGEBG, stroke=ORANGE, sw=2, rx=8, dash="6,4")
    s.text(560, 780, "Observed IoT Traffic (multiple devices)", size=10.6, weight=700, fill="#7c2d12", anchor="middle")

    # Not-a-router callout
    s.rect(60, 630, 300, 180, fill="#fef2f2", stroke=RED, sw=2, rx=10)
    s.text(210, 654, "CIPHER is NOT:", size=11.5, weight=800, fill="#7f1d1d", anchor="middle")
    s.mtext(80, 676, [
        "✗ a wireless access point",
        "✗ a router / NAT gateway",
        "✗ a second Wi-Fi network",
        "",
        "The Pi never bridges or",
        "forwards IoT traffic — it",
        "only observes it via the",
        "monitor-mode adapter,",
        "using the existing,",
        "unmodified capture",
        "pipeline.",
    ], size=9.4, weight=600, fill="#7f1d1d", lh=13.2)

    s.save("network-architecture.svg")


# =====================================================================
# 3. RASPBERRY PI 4 BOARD — TOP VIEW
# =====================================================================
def gen_pi_board():
    s = SVG(960, 700)
    s.text(480, 34, "RASPBERRY PI 4 MODEL B — 4GB (TOP VIEW)", size=16, weight=900, fill=NAVY, anchor="middle")
    bx, by, bw, bh = 140, 130, 600, 400

    # GPIO header top edge (drawn first so board sits below the title with room to spare)
    s.rect(bx + 40, by - 46, 300, 26, fill="#111827", stroke="#000", sw=1.5, rx=2)
    for i in range(20):
        s.circle(bx + 48 + i * 14.8, by - 33, 3.4, fill="silver", stroke="none")
    s.circle(bx + 48, by - 33, 5.5, fill="none", stroke=RED, sw=2.4)
    s.line(bx + 48, by - 70, bx + 48, by - 50, color=RED, sw=2.4)
    s.text(bx + 48, by - 76, "PIN 1", size=11, weight=900, fill=RED, anchor="middle")
    s.text(bx + 360, by - 33, "GPIO header (40-pin)", size=11, weight=800, fill="#334155", anchor="start")

    s.rect(bx, by, bw, bh, fill="#0b3d2e", stroke=NAVY, sw=3, rx=8)

    # USB-C power (left edge)
    s.rect(bx - 14, by + 30, 20, 28, fill="#94a3b8", stroke="#334155", sw=1.5)
    s.text(bx - 24, by + 20, "USB-C power", size=10.5, weight=700, fill=NAVY, anchor="end")

    # micro HDMI x2 (left edge, lower)
    s.rect(bx - 14, by + 80, 18, 14, fill="#94a3b8", stroke="#334155", sw=1.5)
    s.rect(bx - 14, by + 100, 18, 14, fill="#94a3b8", stroke="#334155", sw=1.5)
    s.text(bx - 24, by + 96, "2× micro-HDMI", size=10.5, weight=700, fill=NAVY, anchor="end")

    # USB2/3 right edge
    s.rect(bx + bw - 6, by + 230, 34, 24, fill="#1d4ed8", stroke="#0b1f4d", sw=1.5)
    s.rect(bx + bw - 6, by + 258, 34, 24, fill="#1d4ed8", stroke="#0b1f4d", sw=1.5)
    s.text(bx + bw + 34, by + 250, "2× USB 3.0 (blue)", size=10.5, weight=700, fill=NAVY, anchor="start")

    s.rect(bx + bw - 6, by + 288, 34, 24, fill="#111827", stroke="#000", sw=1.5)
    s.rect(bx + bw - 6, by + 316, 34, 24, fill="#111827", stroke="#000", sw=1.5)
    s.text(bx + bw + 34, by + 308, "2× USB 2.0 (black)", size=10.5, weight=700, fill=NAVY, anchor="start")

    # ethernet right edge
    s.rect(bx + bw - 6, by + 346, 40, 30, fill="#334155", stroke="#000", sw=1.5)
    s.text(bx + bw + 46, by + 366, "Gigabit Ethernet", size=10.5, weight=700, fill=NAVY, anchor="start")

    # SoC
    s.rect(bx + 220, by + 150, 90, 90, fill="#1f2937", stroke="#000", sw=1.5, rx=4)
    s.text(bx + 265, by + 200, "SoC", size=11, weight=700, fill=WHITE, anchor="middle")

    # microSD note (underside)
    s.rect(bx + 40, by + 320, 160, 44, fill="none", stroke=CYAN, sw=2, rx=6, dash="5,4")
    s.text(bx + 120, by + 346, "microSD slot — underside", size=9.8, weight=700, fill=CYAND, anchor="middle")

    s.pill(bx, by + bh + 24, "PORT LOCATIONS: FACTUAL / RASPBERRY PI SPEC", "info", h=20, size=9.2)

    s.save("pi-board-top.svg")


# =====================================================================
# 4. GPIO HEADER + PIN 1 CLOSE-UP  and  WI-FI ROLES
# =====================================================================
def gen_gpio_pin1():
    rows, pitch = 20, 23
    hx, hy = 220, 130
    header_bottom = hy + (rows - 1) * pitch
    s = SVG(820, header_bottom + 260)
    s.text(410, 36, "GPIO HEADER CLOSE-UP — PIN 1 ORIENTATION", size=15, weight=900, fill=NAVY, anchor="middle")

    s.line(hx, 58, hx, hy - 26, color=RED, sw=3)
    s.text(hx, 50, "PIN 1", size=13, weight=900, fill=RED, anchor="middle")

    s.rect(hx - 30, hy - 22, 300, (rows - 1) * pitch + 44, fill="#0f172a", stroke="#000", sw=2, rx=10)
    for r in range(rows):
        for c in range(2):
            pin_no = r * 2 + c + 1
            x = hx + c * 90
            y = hy + r * pitch
            is_pin1 = pin_no == 1
            fill = RED if is_pin1 else "#e5e7eb"
            s.circle(x, y, 6.8, fill=fill, stroke="#111827", sw=1.3)
            if is_pin1:
                s.circle(x, y, 12, fill="none", stroke=RED, sw=2.4)
    s.text(hx - 55, hy + 4, "1", size=12, weight=900, fill=RED, anchor="middle")
    s.text(hx + 90 + 55, hy + 4, "2", size=12, weight=900, fill=WHITE, anchor="middle")
    s.text(hx - 55, header_bottom + 4, "39", size=11, weight=700, fill=WHITE, anchor="middle")
    s.text(hx + 90 + 55, header_bottom + 4, "40", size=11, weight=700, fill=WHITE, anchor="middle")

    ty = header_bottom + 60
    s.mtext(70, ty, [
        "Pin 1 sits at the corner of the 40-pin header nearest the USB-C power",
        "connector (a square solder pad on the underside marks Pin 1 on every",
        "Raspberry Pi board). Physical pin numbers count left-right, top-to-",
        "bottom: 1, 2 in the top row, down to 39, 40 at the far end.",
    ], size=11, weight=600, fill="#334155", lh=20)

    s.pill(70, ty + 96, "PORT / PIN-1 LOCATION: FACTUAL REFERENCE", "info", h=20, size=9.4)
    s.rect(70, ty + 128, 680, 76, fill=REDBG, stroke=RED, sw=2, rx=8)
    s.mtext(90, ty + 154, [
        "This shows the physical header only — it does NOT show which pins CIPHER's",
        "OLED or LEDs use. See “GPIO Assignment — Pending Final Approval” before",
        "connecting anything here.",
    ], size=10.4, weight=700, fill="#7f1d1d", lh=18)

    s.save("gpio-header-pin1.svg")


def gen_wifi_roles():
    s = SVG(820, 480)
    s.text(410, 34, "TWO WI-FI ROLES — EXACTLY ONE EXTERNAL ADAPTER", size=14.5, weight=900, fill=NAVY, anchor="middle")

    # left: built-in
    s.box(60, 80, 320, 100, "Raspberry Pi 4", "Built-in Wi-Fi (on-board)", tsize=15, ssize=11)
    s.pill(75, 168, "MANAGEMENT ROLE", "impl", h=18, size=8.6)
    s.varrow(220, 182, 236, color=NAVY)
    s.box(60, 240, 320, 84, "SSH + Dashboard", "to/from Windows laptop", tsize=13, ssize=10.5)

    # right: external
    s.box(440, 80, 320, 100, "External USB Wi-Fi Adapter", "monitor-mode capable (exactly one)", tsize=15, ssize=11)
    s.pill(455, 168, "MONITORING ROLE", "sw", h=18, size=8.6)
    s.varrow(600, 182, 236, color=NAVY)
    s.box(440, 240, 320, 84, "IoT Traffic Capture", "for CIPHER pipeline (software pending)", tsize=13, ssize=10.5)

    s.rect(60, 350, 700, 96, fill=REDBG, stroke=RED, sw=2.2, rx=10)
    s.text(410, 376, "DO NOT ADD A SECOND EXTERNAL USB Wi-Fi ADAPTER", size=13, weight=900, fill="#7f1d1d", anchor="middle")
    s.text(410, 400, "The project budget and design assume exactly one monitor-mode adapter.", size=10.6, weight=600, fill="#7f1d1d", anchor="middle")
    s.text(410, 420, "Built-in Wi-Fi always stays on the management network — never used for capture.", size=10.6, weight=600, fill="#7f1d1d", anchor="middle")

    s.save("wifi-roles.svg")


# =====================================================================
# 5. OLED / LED / PASSIVE COMPONENTS
# =====================================================================
def gen_components_oled_led():
    s = SVG(820, 620)

    # OLED module
    s.rect(50, 50, 220, 150, fill="#0f172a", stroke=NAVY, sw=2.5, rx=8)
    s.rect(64, 64, 192, 90, fill="#111827", stroke="#000", sw=1)
    s.text(160, 115, "OLED", size=16, weight=800, fill=CYAN, anchor="middle")
    for i, lbl in enumerate(["GND", "VCC", "SCL", "SDA"]):
        s.circle(78 + i * 50, 176, 5, fill="#e5e7eb", stroke="#000")
        s.text(78 + i * 50, 196, lbl, size=10.5, weight=800, fill=CYAN, anchor="middle")
    s.text(160, 220, "SSD1306 I²C OLED (0.96″)", size=12, weight=800, fill=NAVY, anchor="middle")
    s.text(160, 236, "check silkscreen — label order varies by module", size=9, weight=600, fill=GREY, anchor="middle")

    # LEDs
    for i, (name, col) in enumerate([("Green LED", GREEN), ("Amber LED", AMBER), ("Red LED", RED)]):
        x = 330 + i * 160
        s.circle(x + 40, 90, 26, fill=col, stroke=NAVY, sw=2.5)
        s.line(x + 40, 64, x + 30, 40, color=NAVY, sw=2.5, marker=None)
        s.line(x + 40, 64, x + 50, 40, color=NAVY, sw=2.5, marker=None)
        s.mtext(x + 40, 26, ["long leg = anode (+)"], size=8.2, weight=700, fill=GREY, anchor="middle")
        s.text(x + 40, 138, name, size=11.5, weight=800, fill=NAVY, anchor="middle")
        s.text(x + 40, 152, "long leg = anode (+)", size=8.6, weight=600, fill=GREY, anchor="middle")
        s.text(x + 40, 164, "flat side = cathode (−)", size=8.6, weight=600, fill=GREY, anchor="middle")

    # resistor
    s.rect(340, 250, 140, 34, fill="#f5deb3", stroke=NAVY, sw=2, rx=6)
    for i, c in enumerate(["#8b4513", "#000000", "#dc2626", "#d4af37"]):
        s.rect(360 + i * 22, 250, 8, 34, fill=c, stroke="none")
    s.text(410, 300, "Current-limiting resistor", size=11, weight=800, fill=NAVY, anchor="middle")
    s.text(410, 314, "(exact value per LED datasheet / supply voltage)", size=8.6, weight=600, fill=GREY, anchor="middle")

    # jumper wires
    for i in range(3):
        y = 360 + i * 26
        col = [GREEN, AMBER, RED][i]
        s.line(60, y, 260, y, color=col, sw=5, marker=None)
        s.circle(60, y, 7, fill="#d1d5db", stroke="#374151", sw=1.5)
        s.circle(260, y, 7, fill="none", stroke="#374151", sw=1.5)
    s.text(160, 450, "Male-to-female jumper wires", size=11, weight=800, fill=NAVY, anchor="middle")
    s.text(160, 464, "(male end → breadboard, female end → GPIO header)", size=8.6, weight=600, fill=GREY, anchor="middle")

    # breadboard
    s.rect(340, 360, 380, 130, fill="#f8fafc", stroke=NAVY, sw=2, rx=8)
    for r in range(4):
        for c in range(16):
            s.circle(360 + c * 22, 380 + r * 22, 2.6, fill="#94a3b8", stroke="none")
    s.text(530, 508, "Breadboard — only if needed for safe, easy assembly", size=10.5, weight=800, fill=NAVY, anchor="middle")

    s.pill(50, 540, "COMPONENT IDENTIFICATION ONLY — NOT A WIRING DIAGRAM", "info", h=20, size=9.4)
    s.save("oled-led-components.svg")


# =====================================================================
# 6. IMAGER FLOW (microSD / OS setup)
# =====================================================================
def gen_flow(name, steps, title, width=760, height=None, box_h=64, gap=34):
    height = height or (60 + len(steps) * (box_h + gap))
    s = SVG(width, height)
    if title:
        s.text(width / 2, 34, title, size=14.5, weight=900, fill=NAVY, anchor="middle")
        top = 60
    else:
        top = 14
    y = top
    for i, (t, sub) in enumerate(steps):
        s.box(width / 2 - 260, y, 520, box_h, t, sub, tsize=13, ssize=10)
        s.circle(width / 2 - 260 - 24, y + box_h / 2, 16, fill=CYAN, stroke=NAVY, sw=2)
        s.text(width / 2 - 260 - 24, y + box_h / 2 + 5, str(i + 1), size=14, weight=900, fill=NAVY, anchor="middle")
        if i < len(steps) - 1:
            s.varrow(width / 2, y + box_h, y + box_h + gap)
        y += box_h + gap
    s.save(name)
    return s


def gen_imager_flow():
    steps = [
        ("Raspberry Pi Imager (Windows)", "official Raspberry Pi flashing tool"),
        ("Choose OS: Raspberry Pi OS (64-bit)", "matches the ARM64 / Pi 4 target"),
        ("Configure hostname", "e.g. a name you will recognize on the LAN"),
        ("Enable SSH", "so no monitor/keyboard is ever required"),
        ("Configure user credentials", "set your own username + password — never hardcoded"),
        ("Configure management Wi-Fi (if required)", "your trusted network's SSID/credentials"),
        ("Write the card", "Imager flashes + verifies the microSD card"),
        ("Safely eject the microSD card", "before removing it from the laptop"),
    ]
    gen_flow("imager-flow.svg", steps, "MICROSD / OS SETUP — FROM WINDOWS", box_h=56, gap=22)


def gen_ssh_boot_flow():
    steps = [
        ("Insert microSD → power on the Pi", "no monitor or keyboard attached"),
        ("Find the Pi on the trusted network", "router client list, or the configured hostname"),
        ("Connect over SSH", "from the Windows laptop, using the configured user"),
        ("Verify the OS", "confirm Raspberry Pi OS 64-bit is running"),
        ("Verify the IP address", "record it for dashboard access later"),
    ]
    gen_flow("ssh-boot-flow.svg", steps, "FIRST HEADLESS BOOT", box_h=58, gap=26)


def gen_usb_adapter_connect():
    s = SVG(800, 460)
    s.text(400, 34, "CONNECT THE SINGLE USB Wi-Fi ADAPTER", size=14.5, weight=900, fill=NAVY, anchor="middle")
    s.box(50, 70, 270, 150, "Raspberry Pi 4", "powered on, management Wi-Fi active", tsize=13.5, ssize=10)
    s.pill(65, 176, "MANAGEMENT LINK UP", "impl", h=16, size=7.6)
    s.harrow(320, 410, 145, color=NAVY, sw=4)
    s.text(365, 128, "USB", size=11, weight=800, fill=GREY, anchor="middle")
    s.rect(410, 110, 90, 70, fill="#1d4ed8", stroke="#0b1f4d", sw=2, rx=6)
    s.text(455, 150, "USB", size=12, weight=800, fill=WHITE, anchor="middle")
    s.harrow(500, 570, 145, color=NAVY, sw=4)
    s.box(570, 70, 190, 150, "USB Wi-Fi Adapter", "monitor-mode capable", tsize=13, ssize=10)

    s.mtext(60, 260, [
        "1. Connect the single USB Wi-Fi adapter to any free USB port.",
        "2. Identify it from an SSH session:",
    ], size=11.5, weight=700, fill=NAVY, lh=22)
    s.rect(60, 296, 640, 92, fill=NAVY, stroke=NAVY, sw=0, rx=6)
    s.mtext(78, 320, ["lsusb", "ip link", "iw dev"], size=13, weight=600, fill="#d7ecf5",
             family="Consolas, 'Courier New', monospace", lh=24)
    s.text(60, 424, "Do not assume an interface name — record the actual name shown.", size=10.8, weight=700, fill="#7c2d12")
    s.save("usb-adapter-connect.svg")


# =====================================================================
# 7. RASPBERRY PI OFFICIAL HEADER REFERENCE (factual, I2C context only)
# =====================================================================
def gen_pi_header_reference():
    labels = [
        ("3V3 power", "5V power"), ("GPIO2 (SDA)", "5V power"),
        ("GPIO3 (SCL)", "GND"), ("GPIO4", "GPIO14 (TXD)"),
        ("GND", "GPIO15 (RXD)"), ("GPIO17", "GPIO18"),
        ("GPIO27", "GND"), ("GPIO22", "GPIO23"),
        ("3V3 power", "GPIO24"), ("GPIO10 (MOSI)", "GND"),
        ("GPIO9 (MISO)", "GPIO25"), ("GPIO11 (SCLK)", "GPIO8 (CE0)"),
        ("GND", "GPIO7 (CE1)"), ("ID_SD (EEPROM)", "ID_SC (EEPROM)"),
        ("GPIO5", "GND"), ("GPIO6", "GPIO12"),
        ("GPIO13", "GND"), ("GPIO19", "GPIO16"),
        ("GPIO26", "GPIO20"), ("GND", "GPIO21"),
    ]
    hx, hy, pitch = 500, 108, 33
    header_h = len(labels) * pitch + 20
    s = SVG(1000, hy + header_h + 120)
    s.text(500, 34, "RASPBERRY PI 4 — OFFICIAL 40-PIN HEADER (REFERENCE)", size=15, weight=900, fill=NAVY, anchor="middle")
    s.text(500, 56, "Factual hardware pinout — for context only. NOT a CIPHER wiring map.", size=10.8, weight=700, fill="#7c2d12", anchor="middle")

    s.rect(hx - 90, hy - 20, 180, header_h, fill="#0f172a", stroke="#000", sw=2, rx=10)
    for r, (left, right) in enumerate(labels):
        y = hy + r * pitch
        pin_l = r * 2 + 1
        pin_r = r * 2 + 2
        i2c_labels = ("GPIO2 (SDA)", "GPIO3 (SCL)")
        col_l = CYAN if left in i2c_labels else ("#fca5a5" if ("3V3" in left or "5V" in left) else "#e5e7eb")
        col_r = CYAN if right in i2c_labels else ("#fca5a5" if ("3V3" in right or "5V" in right) else "#e5e7eb")
        s.circle(hx - 30, y, 6.5, fill=(RED if pin_l == 1 else col_l), stroke="#111827", sw=1.2)
        s.circle(hx + 30, y, 6.5, fill=col_r, stroke="#111827", sw=1.2)
        # pin numbers sit immediately beside the header pins
        s.text(hx - 42, y + 4, f"{pin_l}", size=9, weight=800, fill=WHITE, anchor="end")
        s.text(hx + 42, y + 4, f"{pin_r}", size=9, weight=800, fill=WHITE, anchor="start")
        # labels sit further out, clear of the header body
        s.text(hx - 100, y + 4, left, size=10, weight=700, fill="#334155", anchor="end")
        s.text(hx + 100, y + 4, right, size=10, weight=700, fill="#334155", anchor="start")

    # legend
    ly = hy + header_h + 30
    s.circle(hx - 260, ly, 6, fill=CYAN, stroke="#111827")
    s.text(hx - 244, ly + 4, "I²C bus 1 (SDA/SCL) — fixed hardware function", size=10.5, weight=700, fill=NAVY, anchor="start")
    s.circle(hx + 40, ly, 6, fill="#fca5a5", stroke="#111827")
    s.text(hx + 56, ly + 4, "Power pins (3V3 / 5V)", size=10.5, weight=700, fill=NAVY, anchor="start")
    s.circle(hx - 260, ly + 26, 6, fill=RED, stroke="#111827")
    s.text(hx - 244, ly + 30, "Pin 1", size=10.5, weight=700, fill=NAVY, anchor="start")

    s.save("pi-header-reference.svg")


# =====================================================================
# 8. LED WIRING CONCEPT (generic, GPIO TBD)
# =====================================================================
def gen_led_wiring_concept():
    s = SVG(780, 360)
    s.text(390, 30, "LED WIRING CONCEPT — GPIO PIN TO BE ASSIGNED", size=14, weight=900, fill=NAVY, anchor="middle")

    x = 60
    s.box(x, 70, 150, 60, "GPIO pin", "(TBD)", fill="#fff7ed", stroke=ORANGE, tsize=13, ssize=10.5)
    s.harrow(x + 150, x + 260, 100, color=NAVY, sw=3.5)
    s.rect(x + 270, 78, 100, 44, fill="#f5deb3", stroke=NAVY, sw=2, rx=6)
    for i, c in enumerate(["#8b4513", "#000000", "#dc2626", "#d4af37"]):
        s.rect(x + 280 + i * 20, 78, 8, 44, fill=c, stroke="none")
    s.text(x + 320, 140, "resistor", size=11, weight=700, fill=NAVY, anchor="middle")
    s.harrow(x + 370, x + 460, 100, color=NAVY, sw=3.5)
    s.circle(x + 500, 100, 30, fill=AMBER, stroke=NAVY, sw=2.5)
    s.text(x + 500, 106, "LED", size=12, weight=800, fill=NAVY, anchor="middle")
    s.harrow(x + 530, x + 620, 100, color=NAVY, sw=3.5)
    s.box(x + 620, 70, 100, 60, "GND", "", fill="#e5e7eb", stroke=NAVY, tsize=13, ssize=10)

    s.mtext(60, 200, [
        "GPIO → resistor → LED (anode) → LED (cathode) → GND",
        "",
        "• Repeat once per LED colour (green / amber / red) once GPIO pins are approved.",
        "• Never connect an LED directly to a GPIO pin without a resistor.",
        "• Confirm LED polarity (long leg / flat side) before connecting.",
    ], size=11.5, weight=600, fill="#334155", lh=22)

    s.rect(60, 300, 660, 46, fill=REDBG, stroke=RED, sw=2, rx=8)
    s.text(390, 328, "Exact GPIO pin numbers are NOT assigned yet — see “GPIO Assignment — Pending”", size=11, weight=800, fill="#7f1d1d", anchor="middle")
    s.save("led-wiring-concept.svg")


# =====================================================================
# 9. LIVE CAPTURE ARCHITECTURE
# =====================================================================
def gen_capture_architecture():
    s = SVG(780, 560)
    s.text(390, 30, "INTENDED MULTI-DEVICE CAPTURE ARCHITECTURE", size=14, weight=900, fill=NAVY, anchor="middle")
    s.pill(280, 42, "SOFTWARE IMPLEMENTATION PENDING", "sw", h=18, size=9)

    devices = ["IoT Device A", "IoT Device B", "IoT Device C"]
    for i, d in enumerate(devices):
        y = 90 + i * 60
        s.box(40, y, 180, 44, d, None, tsize=12)
        s.harrow(220, 340, y + 22, color=GREY, sw=2.4)
    s.rect(340, 80, 40, 200, fill="none", stroke=GREY, sw=2, rx=6)
    s.text(360, 300, "traffic in air", size=9.5, fill=GREY, anchor="middle")

    s.harrow(380, 440, 180, color=NAVY, sw=3.5)
    s.box(440, 130, 200, 100, "External USB Wi-Fi Adapter", "monitor mode (exactly one)", tsize=12, ssize=9.5)
    s.varrow(540, 230, 280, color=NAVY, sw=3.5)
    s.box(440, 284, 200, 70, "CIPHER Pipeline", "existing, unmodified", tsize=12.5, ssize=9.5)
    s.pill(445, 277, "IMPLEMENTED (CORE)", "impl", h=15, size=7.4)
    s.varrow(540, 362, 396, color=NAVY, sw=3.5)
    s.box(410, 400, 260, 58, "Per-Device DeviceAssessment", "identity preserved per src IP", tsize=12, ssize=9.5)

    s.rect(40, 490, 700, 48, fill=ORANGEBG, stroke=ORANGE, sw=2, rx=8)
    s.text(390, 518, "Must NOT reuse Windows host-live normalization — real device identities are preserved here", size=10.3, weight=700, fill="#7c2d12", anchor="middle")
    s.save("capture-architecture.svg")


# =====================================================================
# 10. REPORTING + ENFORCEMENT FLOW
# =====================================================================
def gen_reporting_enforcement_flow():
    s = SVG(780, 640)
    s.text(390, 30, "EXISTING RISK, REPORTING & ENFORCEMENT FLOW", size=14, weight=900, fill=NAVY, anchor="middle")
    steps = [
        ("DeviceAssessment", "QRS + optional Isolation Forest, fused", "impl"),
        ("is_flagged_device()", "final_category != LOW", "impl"),
        ("generate_report()", "3-page PDF: findings + remediation + NIST refs", "impl"),
        ("ML-DSA-44 signature (FIPS 204)", "signs canonical report content (SHA-256 hash)", "impl"),
        ("should_isolate(): raw QRS ≥ 7", "Isolation Forest escalation ALONE never qualifies", "impl"),
        ("NoOpIsolationBackend (Windows)", "requested=True, enforced=False (logged)", "impl"),
        ("Linux enforcement backend", "IMPLEMENTATION PENDING — no iptables/nftables yet", "sw"),
    ]
    y = 70
    for i, (t, sub, kind) in enumerate(steps):
        fill = REDBG if kind == "sw" else WHITE
        stroke = RED if kind == "sw" else NAVY
        s.box(90, y, 600, 58, t, sub, fill=fill, stroke=stroke, tsize=13, ssize=9.6)
        s.pill(700, y + 18, "PENDING" if kind == "sw" else "OK", kind, h=20, size=8)
        if i < len(steps) - 1:
            s.varrow(390, y + 58, y + 80)
        y += 80
    s.save("reporting-enforcement-flow.svg")


# =====================================================================
# 11 & 12. FINAL ASSEMBLY SPREAD (two pages)
# =====================================================================
def gen_final_assembly_1():
    s = SVG(780, 880)
    s.text(390, 34, "FINAL PHYSICAL ASSEMBLY — PART 1 OF 2", size=15, weight=900, fill=NAVY, anchor="middle")
    s.box(230, 60, 320, 66, "Windows Laptop", "SSH + dashboard browser", tsize=14, ssize=11)
    s.pill(250, 134, "IMPLEMENTED", "impl", h=17, size=8)
    s.varrow(390, 152, 202, color=NAVY, sw=3.5)
    s.text(410, 180, "Wi-Fi / LAN management link", size=10.6, weight=700, fill=GREY)
    s.box(190, 206, 400, 62, "Raspberry Pi 4 — Built-in Wi-Fi", "management connection")
    s.varrow(390, 268, 316, color=NAVY, sw=3.5)
    s.rect(120, 320, 540, 320, fill="#f8fbfd", stroke=NAVY, sw=2.6, rx=14)
    s.text(390, 350, "RASPBERRY PI 4", size=15, weight=900, fill=NAVY, anchor="middle")
    s.text(390, 370, "runs CIPHER software (implemented core)", size=10.5, weight=600, fill=GREY, anchor="middle")

    # fan-out arrows to 3 children
    s.line(390, 384, 390, 410, color=NAVY, sw=3)
    s.line(230, 410, 550, 410, color=NAVY, sw=3)
    s.line(230, 410, 230, 434, color=NAVY, sw=3, marker="arrow")
    s.line(390, 410, 390, 434, color=NAVY, sw=3, marker="arrow")
    s.line(550, 410, 550, 434, color=NAVY, sw=3, marker="arrow")

    s.box(150, 440, 160, 84, "OLED", "SSD1306 I²C (pending)", tsize=12.5, ssize=9)
    s.pill(158, 518, "HW PENDING", "hw", h=15, size=7.2)
    s.box(310, 440, 160, 84, "Status LEDs", "Green/Amber/Red (pending)", tsize=12.5, ssize=9)
    s.pill(320, 518, "HW PENDING", "hw", h=15, size=7.2)
    s.box(470, 440, 160, 84, "USB Wi-Fi Adapter", "monitor mode (exactly one)", tsize=12.5, ssize=9)
    s.pill(480, 518, "SW PENDING", "sw", h=15, size=7.2)

    s.mtext(150, 566, [
        "Continued on Part 2 of 2:",
        "• close-up of the USB adapter placement and role",
        "• the observed-IoT-traffic boundary",
        "• the complete labelled component legend",
    ], size=11.5, weight=700, fill="#334155", lh=21)

    s.rect(120, 700, 540, 80, fill=REDBG, stroke=RED, sw=2.2, rx=10)
    s.text(390, 728, "EXACTLY ONE external USB Wi-Fi adapter appears in this assembly.", size=12, weight=800, fill="#7f1d1d", anchor="middle")
    s.text(390, 750, "Built-in Wi-Fi is always the management link — never used for capture.", size=10.5, weight=600, fill="#7f1d1d", anchor="middle")

    s.save("final-assembly-1.svg")


def gen_final_assembly_2():
    s = SVG(780, 700)
    s.text(390, 34, "FINAL PHYSICAL ASSEMBLY — PART 2 OF 2", size=15, weight=900, fill=NAVY, anchor="middle")

    s.box(300, 66, 180, 70, "Raspberry Pi 4", "(continued)", tsize=13, ssize=10)
    s.varrow(390, 136, 176, color=NAVY, sw=3)

    s.rect(60, 180, 660, 330, fill="#f8fbfd", stroke=GREYL, sw=2, rx=12)
    labels = [
        (100, 220, "1", "SSD1306 OLED", "I²C — status display", "hw"),
        (100, 300, "2", "Green LED", "LOW risk indicator (desired)", "hw"),
        (100, 380, "3", "Amber LED", "MEDIUM risk indicator (desired)", "hw"),
        (100, 460, "4", "Red LED", "HIGH risk indicator (desired)", "hw"),
        (430, 220, "5", "Resistors", "one per LED, current-limiting", "hw"),
        (430, 300, "6", "Jumper wires", "male-to-female, GPIO header", "hw"),
        (430, 380, "7", "External USB Wi-Fi Adapter", "monitor-mode capture (exactly one)", "sw"),
        (430, 460, "8", "Observed IoT Traffic", "boundary — not physically wired", "sw"),
    ]
    for x, y, num, name, sub, kind in labels:
        s.circle(x, y, 14, fill=CYAN, stroke=NAVY, sw=2)
        s.text(x, y + 5, num, size=13, weight=900, fill=NAVY, anchor="middle")
        s.text(x + 26, y - 4, name, size=12.5, weight=800, fill=NAVY, anchor="start")
        s.text(x + 26, y + 14, sub, size=9.6, weight=600, fill=GREY, anchor="start")
        w = s.pill(x + 26, y + 22, "HARDWARE PENDING" if kind == "hw" else "SOFTWARE PENDING", kind, h=15, size=7)

    s.text(390, 550, "Every numbered item above is cross-referenced in the final wiring table", size=10.8, weight=700, fill="#334155", anchor="middle")
    s.text(390, 568, "(Section: Complete GPIO Assembly) once GPIO pins are approved.", size=10.8, weight=700, fill="#334155", anchor="middle")

    s.rect(60, 590, 660, 90, fill=AMBERBG, stroke=AMBER, sw=2.2, rx=10)
    s.text(390, 618, "Items 1–6 (OLED, LEDs, resistors, jumper wires):", size=11.5, weight=800, fill="#78350f", anchor="middle")
    s.text(390, 640, "HARDWARE INTEGRATION PENDING — GPIO pin map not yet approved (see dedicated page).", size=10.3, weight=600, fill="#78350f", anchor="middle")
    s.text(390, 660, "Do not wire these until the GPIO assignment page is finalized.", size=10.3, weight=600, fill="#78350f", anchor="middle")

    s.save("final-assembly-2.svg")


# =====================================================================
# 13. COVER EMBLEM
# =====================================================================
def gen_cover_emblem():
    s = SVG(300, 300)
    s.circle(150, 150, 132, fill="none", stroke=CYAN, sw=3)
    s.circle(150, 150, 108, fill="none", stroke=CYAN, sw=1.4)
    # shield
    s.raw(f'<path d="M150,60 L215,88 V158 C215,205 185,235 150,250 '
          f'C115,235 85,205 85,158 V88 Z" fill="{CYAN}" fill-opacity="0.08" stroke="{CYAN}" stroke-width="3"/>')
    # lock body
    s.rect(122, 150, 56, 44, fill=CYAN, stroke=NAVY, sw=2, rx=6)
    s.raw(f'<path d="M134,150 v-16 a16,16 0 0 1 32,0 v16" fill="none" stroke="{CYAN}" stroke-width="6"/>')
    s.circle(150, 172, 6, fill=NAVY)
    # circuit traces
    for (x1, y1, x2, y2) in [(150, 88, 150, 112), (108, 120, 130, 140), (192, 120, 170, 140)]:
        s.line(x1, y1, x2, y2, color=CYAN, sw=2, marker=None)
    for (cx, cy) in [(150, 88), (108, 120), (192, 120)]:
        s.circle(cx, cy, 4, fill=CYAN, stroke="none")
    s.save("cover-emblem.svg")


# =====================================================================
# 14. BOM ICON SET (simple, reusable pictograms)
# =====================================================================
def _icon(vb, body):
    return f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {vb} {vb}">{body}</svg>'


def gen_bom_icons():
    icons = {}
    icons["pi"] = _icon(100, f'<rect x="10" y="14" width="80" height="60" rx="6" fill="#0b3d2e" stroke="{NAVY}" stroke-width="3"/>'
                              f'<rect x="18" y="4" width="40" height="10" fill="#111827"/>'
                              f'<circle cx="55" cy="44" r="10" fill="#1f2937"/>')
    icons["sdcard"] = _icon(100, f'<path d="M25,10 h40 l10,10 v65 h-60 v-65 Z" fill="#1d4ed8" stroke="{NAVY}" stroke-width="3"/>'
                                  f'<rect x="35" y="20" width="8" height="18" fill="#facc15"/>'
                                  f'<rect x="47" y="20" width="8" height="18" fill="#facc15"/>')
    icons["power"] = _icon(100, f'<rect x="30" y="10" width="40" height="55" rx="8" fill="#334155" stroke="{NAVY}" stroke-width="3"/>'
                                 f'<rect x="44" y="65" width="12" height="20" fill="#111827"/>'
                                 f'<circle cx="50" cy="30" r="8" fill="{CYAN}"/>')
    icons["usbwifi"] = _icon(100, f'<rect x="25" y="35" width="45" height="22" rx="4" fill="#111827" stroke="{NAVY}" stroke-width="3"/>'
                                   f'<rect x="15" y="42" width="14" height="8" fill="#94a3b8"/>'
                                   f'<path d="M60,35 q10,-20 20,-25" fill="none" stroke="{CYAN}" stroke-width="3"/>'
                                   f'<path d="M60,35 q16,-14 26,-10" fill="none" stroke="{CYAN}" stroke-width="3"/>')
    icons["oled"] = _icon(100, f'<rect x="15" y="20" width="70" height="45" rx="4" fill="#0f172a" stroke="{NAVY}" stroke-width="3"/>'
                                f'<rect x="25" y="28" width="50" height="22" fill="#111827"/>'
                                f'<text x="50" y="43" font-size="10" fill="{CYAN}" text-anchor="middle" font-family="Arial">OLED</text>')
    for name, col in [("led_g", GREEN), ("led_a", AMBER), ("led_r", RED)]:
        icons[name] = _icon(100, f'<circle cx="50" cy="45" r="26" fill="{col}" stroke="{NAVY}" stroke-width="3"/>'
                                  f'<line x1="40" y1="18" x2="34" y2="4" stroke="{NAVY}" stroke-width="3"/>'
                                  f'<line x1="60" y1="18" x2="66" y2="4" stroke="{NAVY}" stroke-width="3"/>')
    icons["resistor"] = _icon(100, f'<line x1="5" y1="50" x2="30" y2="50" stroke="{NAVY}" stroke-width="3"/>'
                                    f'<rect x="30" y="38" width="40" height="24" rx="5" fill="#f5deb3" stroke="{NAVY}" stroke-width="3"/>'
                                    f'<rect x="38" y="38" width="6" height="24" fill="#8b4513"/>'
                                    f'<rect x="48" y="38" width="6" height="24" fill="#000"/>'
                                    f'<rect x="58" y="38" width="6" height="24" fill="#dc2626"/>'
                                    f'<line x1="70" y1="50" x2="95" y2="50" stroke="{NAVY}" stroke-width="3"/>')
    icons["jumper"] = _icon(100, f'<line x1="10" y1="50" x2="90" y2="50" stroke="{GREEN}" stroke-width="6"/>'
                                  f'<circle cx="10" cy="50" r="8" fill="#d1d5db" stroke="{NAVY}" stroke-width="2"/>'
                                  f'<circle cx="90" cy="50" r="6" fill="none" stroke="{NAVY}" stroke-width="2"/>')
    icons["breadboard"] = _icon(100, f'<rect x="10" y="20" width="80" height="55" rx="4" fill="#f8fafc" stroke="{NAVY}" stroke-width="3"/>'
                                      + "".join(f'<circle cx="{18+c*8}" cy="{34+r*14}" r="2" fill="#94a3b8"/>' for r in range(3) for c in range(9)))
    icons["laptop"] = _icon(100, f'<rect x="15" y="15" width="70" height="45" rx="3" fill="#1f2937" stroke="{NAVY}" stroke-width="3"/>'
                                  f'<rect x="20" y="20" width="60" height="35" fill="{CYAN}"/>'
                                  f'<path d="M8,62 h84 l-6,14 h-72 Z" fill="#334155" stroke="{NAVY}" stroke-width="2"/>')
    for k, v in icons.items():
        with open(os.path.join(OUT_DIR, f"icon-{k}.svg"), "w", encoding="utf-8") as f:
            f.write(v)
        print("wrote icon", k)


if __name__ == "__main__":
    gen_system_overview()
    gen_network_architecture()
    gen_pi_board()
    gen_gpio_pin1()
    gen_wifi_roles()
    gen_components_oled_led()
    gen_imager_flow()
    gen_ssh_boot_flow()
    gen_usb_adapter_connect()
    gen_pi_header_reference()
    gen_led_wiring_concept()
    gen_capture_architecture()
    gen_reporting_enforcement_flow()
    gen_final_assembly_1()
    gen_final_assembly_2()
    gen_cover_emblem()
    gen_bom_icons()
    print("done")
