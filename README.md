# Explainable Machine Learning Architecture for Software Vulnerability and Bug Detection

## Project Overview
This project presents an explainable machine learning framework to detect and interpret software vulnerabilities and bugs using code metrics. It combines a high-accuracy Random Forest Classifier with SHAP (SHapley Additive exPlanations) to ensure transparent decision-making.

## Project Structure
- `create_dataset.py`: Generates the synthetic code metric dataset.
- `code_vulnerability_dataset.csv`: Dataset containing features like lines of code, cyclomatic complexity, etc.
- `train_model.py`: Trains the Random Forest Classifier and saves the model.
- `vulnerability_model.pkl`: Serialized trained machine learning model.
- `explain_model.py`: Computes SHAP values and generates interpretability plots.
- `shap_summary.png`: Visualization of feature contributions.

## Requirements
- Python 3.15.2
- pandas, numpy, scikit-learn, shap, joblib, matplotlib

## Usage
1. Run `python create_dataset.py` to generate the dataset.
2. Run `python train_model.py` to train the model.
3. Run `python explain_model.py` to generate SHAP explanations.