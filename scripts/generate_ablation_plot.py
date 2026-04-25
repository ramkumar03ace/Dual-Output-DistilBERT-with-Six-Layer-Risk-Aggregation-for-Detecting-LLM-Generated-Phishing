import matplotlib.pyplot as plt
import numpy as np

# Data
layers = ["Text Only", "+ URL", "+ Headers", "+ Links", "+ Visual", "+ AI Auth\n(Full System)"]
accuracy = [84.3, 90.8, 94.5, 96.8, 98.4, 99.1]
fnr = [15.7, 9.2, 5.5, 3.2, 1.6, 0.9]

fig, ax1 = plt.subplots(figsize=(10, 6))

color1 = 'tab:blue'
ax1.set_ylabel('Accuracy (%)', color=color1, fontsize=18, fontweight='bold', labelpad=15)
line1 = ax1.plot(layers, accuracy, marker='o', markersize=12, linewidth=4, color=color1, label='Overall Accuracy (%)')
ax1.tick_params(axis='y', labelcolor=color1, labelsize=16)
ax1.set_ylim(80, 100)

ax1.tick_params(axis='x', rotation=45, labelsize=16)

ax2 = ax1.twinx()  
color2 = 'tab:red'
ax2.set_ylabel('False Negative Rate (%)', color=color2, fontsize=18, fontweight='bold', labelpad=15)
line2 = ax2.plot(layers, fnr, linestyle='--', marker='s', markersize=12, linewidth=4, color=color2, label='False Negative Rate (%)')
ax2.tick_params(axis='y', labelcolor=color2, labelsize=16)
ax2.set_ylim(0, 20)

plt.title('Performance Gains via Cumulative Layer Integration\n(Challenging LLM-Phishing Subset)', fontsize=20, pad=20)

lines = line1 + line2
labels = [l.get_label() for l in lines]
ax1.legend(lines, labels, loc='lower left', bbox_to_anchor=(0, -0.4), fontsize=14, framealpha=1, edgecolor='black')

ax1.grid(axis='y', linestyle=':', color='gray', alpha=0.7, linewidth=1.5)

plt.tight_layout()
plt.subplots_adjust(bottom=0.3)

output_path = r"d:\VIT\VIT Sem 8\Sem Project 2\Dual-Output-DistilBERT-with-Six-Layer-Risk-Aggregation-for-Detecting-LLM-Generated-Phishing\docs\Papers\ablation_study_ieee.png"
plt.savefig(output_path, dpi=300, bbox_inches='tight')
print(f"Plot saved successfully to {output_path}")
