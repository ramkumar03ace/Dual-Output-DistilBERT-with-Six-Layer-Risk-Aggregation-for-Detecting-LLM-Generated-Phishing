import matplotlib.pyplot as plt
import numpy as np
import os

# Create docs directory if it doesn't exist
os.makedirs(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'docs'), exist_ok=True)

# Data for V2 Corpus
categories = ['Legitimate', 'Human-Phishing', 'LLM-Phishing']
counts = [4983, 3617, 1000]

# IEEE Paper Styling (Single column width is 3.5 inches)
plt.rcParams.update({
    'font.family': 'serif',
    'font.serif': ['Times New Roman'],
    'font.size': 10,
    'axes.titlesize': 10,
    'axes.labelsize': 10,
    'xtick.labelsize': 9,
    'ytick.labelsize': 9,
    'figure.figsize': (3.5, 2.5), 
    'figure.dpi': 300
})

fig, ax = plt.subplots()

# Use greyscale or pattern-friendly colors for traditional IEEE papers
# We'll use distinct colors but keep them professional
colors = ['#4CAF50', '#F44336', '#FF9800']
bars = ax.bar(categories, counts, color=colors, edgecolor='black', width=0.6, zorder=3)

# Add grid lines behind the bars
ax.grid(axis='y', linestyle='--', alpha=0.7, zorder=0)

# Add value text on top of bars
for bar in bars:
    height = bar.get_height()
    ax.text(bar.get_x() + bar.get_width()/2., height + 100,
            f'{height:,}',
            ha='center', va='bottom', fontsize=9, fontweight='bold')

# Formatting
ax.set_ylabel('Number of Samples')
ax.set_ylim(0, 5800)
ax.set_title('Dataset Composition (V2 Corpus)', pad=10)

plt.tight_layout()

# Save the plot
output_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'docs', 'dataset_composition_ieee.png')
plt.savefig(output_file, dpi=300, bbox_inches='tight')
print(f"Plot successfully saved to {output_file}")
