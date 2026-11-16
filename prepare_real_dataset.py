import re
import csv
import requests
import time

print("1. Fetching Real-World Dataset (CodeXGLUE/Devign) via Hugging Face JSON API...")

base_url = "https://datasets-server.huggingface.co/rows"
dataset_name = "google/code_x_glue_cc_defect_detection"
config = "default"
split = "train"

def extract_security_features(code_str):
    code_text = str(code_str)
    lines = code_text.splitlines()
    loc = len(lines)
    
    # Cyclomatic complexity approximation
    branches = len(re.findall(r'\b(if|else|for|while|case|catch|\&\&|\|\|)\b', code_text))
    cyclomatic_complexity = branches + 1
    
    # Variable declarations count
    num_variables = len(re.findall(r'\b(int|char|float|double|void|long|short|unsigned|var|let|const)\s+[a-zA-Z_]\w*', code_text))
    
    # Unsafe functions count
    unsafe_patterns = r'\b(gets|strcpy|strcat|sprintf|vsprintf|scanf|memcpy|eval|exec|system|popen|innerHTML)\b'
    unsafe_functions_count = len(re.findall(unsafe_patterns, code_text))
    
    # Missing input validation check
    has_validation = 1 if re.search(r'\b(sizeof|strlen|NULL|nullptr|len\(|isinstance)\b', code_text) else 0
    missing_input_validation = 1 if (unsafe_functions_count > 0 and has_validation == 0) else 0
    
    # Hardcoded credentials check
    hardcoded_credentials = 1 if re.search(r'(password|passwd|secret|api_key|token)\s*=\s*["\'][^"\']+["\']', code_text, re.IGNORECASE) else 0
    
    return [
        loc,
        cyclomatic_complexity,
        num_variables,
        unsafe_functions_count,
        missing_input_validation,
        hardcoded_credentials
    ]

output_file = "real_vulnerability_dataset.csv"
headers = [
    "loc",
    "cyclomatic_complexity",
    "num_variables",
    "unsafe_functions_count",
    "missing_input_validation",
    "hardcoded_credentials",
    "label"
]

total_to_fetch = 2000  # Fetching 2,000 real-world functions in batches of 100
batch_size = 100
records_written = 0

with open(output_file, mode="w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(headers)
    
    for offset in range(0, total_to_fetch, batch_size):
        params = {
            "dataset": dataset_name,
            "config": config,
            "split": split,
            "offset": offset,
            "length": batch_size
        }
        response = requests.get(base_url, params=params, timeout=30)
        response.raise_for_status()
        rows = response.json().get("rows", [])
        
        for item in rows:
            row_data_dict = item["row"]
            code = row_data_dict["func"]
            target = int(row_data_dict["target"])
            
            features = extract_security_features(code) + [target]
            writer.writerow(features)
            records_written += 1
            
        print(f"Processed {records_written}/{total_to_fetch} real-world records...")
        time.sleep(0.2)

print(f"Completed! '{output_file}' has been generated successfully with {records_written} real-world records.")