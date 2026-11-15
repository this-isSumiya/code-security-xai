# Explainable Machine Learning Architecture for Software Vulnerability and Bug Detection

## Project Overview
This project presents an explainable machine learning framework to detect, interpret, and automatically remediate software vulnerabilities and bugs using code metrics and Abstract Syntax Tree (AST) parsing. It combines a high-accuracy Random Forest Classifier with **SHAP (SHapley Additive exPlanations)** to ensure transparent decision-making alongside automated security patching.

## Project Structure
* **`ast_parser.py`** : Extracts security metrics (unsafe functions, hardcoded credentials, cyclomatic complexity) using pure Python AST parsing.
* **`patch_generator.py`** : Implements automated remediation and secure patching for identified code vulnerabilities.
* **`run_pipeline.py`** : Orchestrates code parsing, risk scoring, auto-patching, and visual SHAP reporting.
* **`create_dataset.py`** : Generates the synthetic code metric dataset.
* **`code_vulnerability_dataset.csv`** : Dataset containing features like lines of code, cyclomatic complexity, etc.
* **`train_model.py`** : Trains the Random Forest Classifier and saves the model.
* **`vulnerability_model.pkl`** : Serialized trained machine learning model.
* **`explain_model.py`** : Computes SHAP values and generates interpretability plots.
* **`shap_summary.png`** : Visualization of feature contributions and model explainability.

## How It Works (Workflow)
1. **Static Analysis & AST Parsing:** 
   The system parses the target Python source code using Abstract Syntax Trees (`ast_parser.py`) to extract critical security features such as unsafe function calls, hardcoded secrets, and cyclomatic complexity.
2. **Machine Learning Risk Assessment:** 
   The extracted metrics are fed into the trained Random Forest model to calculate a vulnerability risk probability score.
3. **Explainable AI (XAI) Integration:** 
   Using **SHAP**, the system computes feature contributions and generates visual summary plots (`shap_summary.png`) to explain *why* a particular code snippet was flagged as vulnerable.
4. **Automated Remediation (Auto-Patching):** 
   If vulnerabilities or insecure patterns are detected, the `patch_generator.py` module automatically formulates secure code alternatives and remediation patches.

## Requirements
* Python 3.15.2
* `pandas`, `numpy`, `scikit-learn`, `shap`, `joblib`, `matplotlib`

## Usage
1. Run `python create_dataset.py` to generate the dataset.
2. Run `python train_model.py` to train the model.
3. Run `python explain_model.py` to generate SHAP explanations.
4. Run `python run_pipeline.py` to execute the full security scan, risk assessment, and auto-remediation pipeline.
