import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import shap
import joblib

print("1. Loading dataset...")
df = pd.read_csv("code_vulnerability_dataset.csv")

# Features and Target separation (using 'is_vulnerable' column)
X = df.drop(columns=['is_vulnerable'])
y = df['is_vulnerable']

print("2. Splitting dataset into training and testing sets...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print("3. Training Random Forest Classifier...")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Model Evaluation
y_pred = model.predict(X_test)
print("\n--- Model Performance ---")
print(f"Accuracy: {accuracy_score(y_test, y_pred) * 100:.2f}%")
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# Save the trained model
joblib.dump(model, "vulnerability_model.pkl")
print("\n4. Model saved successfully as 'vulnerability_model.pkl'!")