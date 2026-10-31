import pandas as pd
import numpy as np

# Seed for reproducibility
np.random.seed(42)

# Generate synthetic data for 500 code samples
n_samples = 500

data = {
    'lines_of_code': np.random.randint(10, 500, n_samples),
    'cyclomatic_complexity': np.random.randint(1, 30, n_samples),
    'num_variables': np.random.randint(1, 50, n_samples),
    'unsafe_functions_count': np.random.randint(0, 5, n_samples),
    'missing_input_validation': np.random.choice([0, 1], size=n_samples, p=[0.6, 0.4]),
    'hardcoded_credentials': np.random.choice([0, 1], size=n_samples, p=[0.8, 0.2]),
}

df = pd.DataFrame(data)

# Target logic: A code is vulnerable if it uses unsafe functions, lacks validation, or has high complexity
df['is_vulnerable'] = (
    (df['unsafe_functions_count'] * 2) + 
    (df['missing_input_validation'] * 3) + 
    (df['hardcoded_credentials'] * 4) + 
    (df['cyclomatic_complexity'] > 18).astype(int) * 2
) > 4

df['is_vulnerable'] = df['is_vulnerable'].astype(int)

# Save to CSV
df.to_csv('code_vulnerability_dataset.csv', index=False)
print("✅ Dataset successfully generated and saved as 'code_vulnerability_dataset.csv'!")
print(df.head())