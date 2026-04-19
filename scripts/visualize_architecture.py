import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Rectangle
import os

os.makedirs(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'docs'), exist_ok=True)

# Set IEEE styling
plt.rcParams.update({
    'font.family': 'serif',
    'font.serif': ['Times New Roman'],
    'font.size': 9,
    'figure.dpi': 300
})

fig, ax = plt.subplots(figsize=(7, 6.5)) # Wider for architecture
ax.set_xlim(0, 100)
ax.set_ylim(0, 100)
ax.axis('off')

def draw_box(ax, x, y, width, height, text, facecolor='#ffffff', edgecolor='#000000', text_color='black', weight='normal', fontsize=9):
    box = FancyBboxPatch((x, y), width, height,
                         boxstyle="round,pad=0.1,rounding_size=1",
                         linewidth=1.2, edgecolor=edgecolor, facecolor=facecolor, zorder=2)
    ax.add_patch(box)
    ax.text(x + width/2, y + height/2, text,
            ha='center', va='center', fontsize=fontsize, color=text_color, fontweight=weight, zorder=3)

def draw_arrow(ax, x1, y1, x2, y2):
    ax.annotate("",
                xy=(x2, y2), xycoords='data',
                xytext=(x1, y1), textcoords='data',
                arrowprops=dict(arrowstyle="->", color="black", lw=1.2, shrinkA=0, shrinkB=0),
                zorder=1)

def draw_line(ax, x1, y1, x2, y2):
    ax.plot([x1, x2], [y1, y2], color="black", lw=1.2, zorder=1)

# Drawing Input -> Parser
draw_box(ax, 35, 90, 30, 6, "Incoming Email\n(Text, URLs, Headers)", facecolor='#E3F2FD')
draw_arrow(ax, 50, 90, 50, 85)
draw_box(ax, 35, 79, 30, 6, "Email Parser & Preprocessor", facecolor='#FFF3E0')

line_y = 75
draw_arrow(ax, 50, 79, 50, line_y)
draw_line(ax, 15, line_y, 85, line_y)

# 6 Layers + Sender Analysis
layers = [
    ("Layer 1:\nText Classifier\n(DistilBERT)\n20%", 5, 55, 14, 16),
    ("Layer 2:\nURL Intelligence\n\n20%", 20, 55, 14, 16),
    ("Layer 3:\nWeb Crawler\n(Playwright)\n10%", 35, 55, 14, 16),
    ("Layer 4:\nVisual Analysis\n\n15%", 50, 55, 14, 16),
    ("Layer 5:\nLink Checker\n\n15%", 65, 55, 14, 16),
    ("Layer 6:\nHeader Forensics\n\n15%", 80, 55, 14, 16),
]

for text, x, y, w, h in layers:
    draw_arrow(ax, x+w/2, line_y, x+w/2, y+h)
    draw_box(ax, x, y, w, h, text, facecolor='#F1F8E9')
    draw_arrow(ax, x+w/2, y, x+w/2, 45)

# Sender Analysis Box
draw_box(ax, 5, 38, 14, 6, "Sender Auth\n(5%)", facecolor='#F1F8E9')
draw_line(ax, 12, 10, 12, 45) # we will connect sender auth to aggregator
draw_arrow(ax, 12, 38, 12, 30)

# Connect everything to aggregator
draw_line(ax, 27, 45, 87, 45)
draw_arrow(ax, 50, 45, 50, 36)

draw_box(ax, 30, 30, 40, 6, "Weighted Risk Aggregator\n(Scoring & Graduated Layer Boost)", facecolor='#E8EAF6', weight='bold')

# Add Modifiers
draw_box(ax, 5, 29, 20, 8, "Modifier:\nAI Authorship\nDetection", facecolor='#FCE4EC')
draw_arrow(ax, 25, 33, 30, 33)

draw_box(ax, 75, 29, 20, 8, "Modifier:\nExplainable AI\n(XAI) Engine", facecolor='#FCE4EC')
draw_arrow(ax, 75, 33, 70, 33)

draw_arrow(ax, 50, 30, 50, 22)

draw_box(ax, 38, 14, 24, 8, "Final Verdict\n(Phishing / Suspicious / Safe)", facecolor='#FFF9C4', weight='bold')

plt.title("System Architecture of Dual-Output-DistilBERT-with-Six-Layer-Risk-Aggregation-for-Detecting-LLM-Generated-Phishing", y=0.98, fontsize=11, fontweight='bold')
plt.tight_layout()

# Save
output_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'docs', 'system_architecture_ieee.png')
plt.savefig(output_file, dpi=300, bbox_inches='tight')
print(f"Plot successfully saved to {output_file}")
