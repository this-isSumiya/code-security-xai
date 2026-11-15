import os
from ast_parser import extract_code_metrics
from patch_generator import generate_secure_patch
import matplotlib.pyplot as plt
import matplotlib.image as mpimg

# Sample source code for testing (or AI-generated code)
sample_code = """
def authenticate_user():
    password = "SuperSecretPassword123"
    user_input = input("Enter command: ")
    eval(user_input)
    
    if user_input == "admin":
        print("Welcome admin")
    else:
        print("Access denied")
"""

def show_shap_plot():
    """Displays the SHAP Summary Plot if available."""
    plot_path = "shap_summary.png"
    if os.path.exists(plot_path):
        print("\n--- OPENING EXPLAINABLE AI (SHAP) PLOT ---")
        img = mpimg.imread(plot_path)
        plt.figure(figsize=(10, 6))
        plt.imshow(img)
        plt.axis('off')
        plt.title("SHAP Summary Plot - Vulnerability Detection")
        plt.show()
    else:
        print("\n⚠️ SHAP summary plot image not found in the directory.")

def analyze_and_patch(source_code):
    # 1. Extract metrics using AST parser
    metrics = extract_code_metrics(source_code)
    
    # 2. Calculate risk score
    risk_score = (
        (metrics['unsafe_functions_count'] * 2) +
        (metrics['missing_input_validation'] * 3) +
        (metrics['hardcoded_credentials'] * 4) +
        (1 if metrics['cyclomatic_complexity'] > 10 else 0)
    )
    
    is_vulnerable = 1 if risk_score > 4 else 0
    risk_probability = min(0.95, max(0.15, risk_score / 10.0))
    
    # 3. Print Security Report
    print("=" * 50)
    print("   AI-GENERATED CODE SECURITY & AUTO-REMEDIATION REPORT   ")
    print("=" * 50)
    print(f"Extracted Metrics: {metrics}")
    print(f"Prediction: {'⚠️ Vulnerable / Risky' if is_vulnerable == 1 else '✅ Safe'}")
    print(f"Risk Probability: {risk_probability*100:.2f}%")
    
    # 4. Generate Auto-Patch if vulnerable
    if is_vulnerable:
        print("\n--- GENERATING SECURE AUTO-PATCH ---")
        patched_code, fixes = generate_secure_patch(source_code)
        print("Applied Fixes:")
        for fix in fixes:
            print(f"  ✔ {fix}")
        print("\nPatched Code Preview:")
        print("-" * 50)
        print(patched_code)
        print("-" * 50)
    else:
        print("\n✅ Code is secure. No auto-patching required.")
    
    print("=" * 50)
    
    # 5. Show SHAP Explainability Plot
    show_shap_plot()

if __name__ == "__main__":
    analyze_and_patch(sample_code)