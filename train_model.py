import csv
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib

print("1. Loading real-world dataset...")
X_list = []
y_list = []

with open("real_vulnerability_dataset.csv", mode="r", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    feature_cols = [
        "lines_of_code",
        "cyclomatic_complexity",
        "num_variables",
        "unsafe_functions_count",
        "missing_input_validation",
        "hardcoded_credentials"
    ]
    for row in reader:
        X_list.append([float(row[col]) for col in feature_cols])
        y_list.append(int(row["is_vulnerable"]))

X = np.array(X_list)
y = np.array(y_list)

print(f"Loaded {len(y)} real-world samples with {X.shape[1]} AST/security features.")

print("2. Splitting dataset into training and testing sets...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print("3. Training Random Forest Classifier on real-world data...")
model = RandomForestClassifier(n_estimators=150, max_depth=12, random_state=42)
model.fit(X_train, y_train)

# Model Evaluation
y_pred = model.predict(X_test)
print("\n--- Real-World Model Performance ---")
print(f"Accuracy: {accuracy_score(y_test, y_pred) * 100:.2f}%")
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# Save the re-trained model
joblib.dump(model, "vulnerability_model.pkl")
print("4. Re-trained model saved successfully as 'vulnerability_model.pkl'!")