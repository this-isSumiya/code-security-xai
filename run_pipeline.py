import re
import joblib
import warnings
from multi_lang_parser import extract_features
from patch_generator import generate_secure_patch

warnings.filterwarnings("ignore", category=UserWarning)

# Load the pre-trained Random Forest vulnerability classification model
model = joblib.load("vulnerability_model.pkl")

def scan_any_code(file_path):
    """Run end-to-end vulnerability analysis and auto-patching matching exact model features."""
    features = extract_features(file_path)
    lang = features["language"].upper()
    code = features["raw_code"]

    # Calculate variable count and missing input validation across languages
    var_matches = re.findall(r'\b(int|char|float|double|var|let|const|String)\b|=', code)
    num_variables = max(1, len(var_matches))
    
    has_unsafe = features["unsafe_function_count"] > 0
    has_validation = bool(re.search(r'\b(if|validate|sanitize|check|try|catch|isinstance|sizeof)\b', code))
    missing_input_validation = 1 if (has_unsafe and not has_validation) else 0

    # Exact feature mapping matching the trained Random Forest model
    metric_map = {
        "lines_of_code": features["lines_of_code"],
        "cyclomatic_complexity": features["cyclomatic_complexity"],
        "num_variables": num_variables,
        "unsafe_functions_count": features["unsafe_function_count"],
        "missing_input_validation": missing_input_validation,
        "hardcoded_credentials": features["hardcoded_credentials"]
    }

    expected_cols = list(model.feature_names_in_)
    row = [metric_map.get(col, 0) for col in expected_cols]
    feature_vector = [row]

    # Predict vulnerability status and risk probability
    prediction = model.predict(feature_vector)[0]
    risk_prob = model.predict_proba(feature_vector)[0][1] * 100

    print(f"\n==================== Scan Report ({lang}) ====================")
    print(f"File: {file_path}")
    print(f"Metrics: LOC={features['lines_of_code']}, Complexity={features['cyclomatic_complexity']}, "
          f"Unsafe Calls={features['unsafe_function_count']}, Hardcoded Secrets={features['hardcoded_credentials']}")
    print(f"Risk Score: {risk_prob:.2f}% | Status: {'VULNERABLE' if prediction == 1 else 'SAFE'}")

    # Explainability breakdown based on model feature importances
    importances = model.feature_importances_
    print("Model Feature Weights (Risk Drivers):")
    for name, val, imp in zip(expected_cols, row, importances):
        print(f" - {name} (value={val}): weight={imp:.4f}")

    # Generate automated security patches if vulnerabilities are detected
    if prediction == 1:
        patched_code, fixes = generate_secure_patch(code, features["language"])
        print("\nApplied Auto-Patches:")
        for fix in fixes:
            print(f" - {fix}")
        print("\n--- Patched Code Preview ---")
        print(patched_code)
        return patched_code
        
    return code

if __name__ == "__main__":
    # Create temporary sample files to test multi-language detection
    with open("sample_test.c", "w") as f:
        f.write('#include <stdio.h>\nint main() {\n    char buf[10];\n    char *password = "secret123";\n    gets(buf);\n    return 0;\n}')

    with open("sample_test.js", "w") as f:
        f.write('const api_key = "AIzaSy-998877";\nfunction run(userInput) {\n    document.getElementById("out").innerHTML = userInput;\n    eval(userInput);\n}')

    scan_any_code("sample_test.c")
    scan_any_code("sample_test.js")