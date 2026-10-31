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
plt.figure()
# Handling binary classification shap values format
if isinstance(shap_values, list):
    shap.summary_plot(shap_values[1], X, show=False)
else:
    shap.summary_plot(shap_values, X, show=False)

plt.title("SHAP Summary Plot - Vulnerability Detection")
plt.tight_layout()
plt.savefig("shap_summary.png")
print("\n4. Success! SHAP summary plot saved as 'shap_summary.png'.")
plt.show()