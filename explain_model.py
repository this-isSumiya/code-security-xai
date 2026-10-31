import pandas as pd
import shap
import joblib
import matplotlib.pyplot as plt

print("1. Loading saved model and dataset...")
model = joblib.load("vulnerability_model.pkl")
df = pd.read_csv("code_vulnerability_dataset.csv")

# Separate features
X = df.drop(columns=['is_vulnerable'])

print("2. Calculating SHAP values using TreeExplainer...")
explainer = shap.TreeExplainer(model)
shap_values = explainer.shap_values(X)

print("3. Generating and saving SHAP Summary Plot...")
plt.figure(figsize=(10, 6))


import numpy as np
if isinstance(shap_values, list):
    vals = np.array(shap_values[1])
else:
    vals = np.array(shap_values)
    if len(vals.shape) == 3:
        vals = vals[:, :, 1]


shap.summary_plot(vals, X, show=False)

plt.title("SHAP Summary Plot - Vulnerability Detection", fontsize=14, pad=20)
plt.tight_layout()
plt.savefig("shap_summary.png", bbox_inches='tight', dpi=300)
print("\n4. Success! SHAP summary plot saved as 'shap_summary.png'.")
plt.show()