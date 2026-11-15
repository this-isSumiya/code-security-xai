import re
from ast_parser import extract_code_metrics

def generate_secure_patch(source_code):
    """
    Analyzes the source code for common vulnerabilities (like eval or hardcoded credentials)
    and automatically applies security patches to generate a secure version.
    """
    patched_code = source_code
    patches_applied = []

    # 1. Patch: Replace unsafe 'eval(' with a safer alternative or a warning comment/safe parser
    if "eval(" in patched_code:
        # Replacing eval with a safe literal eval or a secure placeholder warning
        patched_code = re.sub(r'\beval\s*\(', '# [AUTO-PATCHED] Unsafe eval removed\n    # ast.literal_eval should be used safely\n    # eval(', patched_code)
        patches_applied.append("Replaced unsafe 'eval()' function.")

    # 2. Patch: Fix hardcoded credentials by masking or replacing with environment variables
    # Example pattern matching strings assigned to password/secret variables
    if re.search(r'(password|secret|api_key)\s*=\s*[\"\'].*?[\"\']', patched_code, re.IGNORECASE):
        patched_code = re.sub(
            r'((password|secret|api_key)\s*=\s*)([\"\']).*?([\"\'])',
            r'\1os.getenv("\2_ENV", "REDACTED_SECURE_PLACEHOLDER") # [AUTO-PATCHED] Moved to env variable',
            patched_code,
            flags=re.IGNORECASE
        )
        patches_applied.append("Secured hardcoded credentials using environment variables.")

    # 3. Ensure 'os' module is imported if os.getenv is introduced
    if "os.getenv" in patched_code and "import os" not in patched_code:
        patched_code = "import os\n" + patched_code

    return patched_code, patches_applied

if __name__ == "__main__":
    # Test sample with vulnerabilities
    test_code = """
def authenticate_user():
    password = "SuperSecretPassword123"
    user_input = input("Enter command: ")
    eval(user_input)
    
    if user_input == "admin":
        print("Welcome admin")
    else:
        print("Access denied")
"""
    print("--- ORIGINAL CODE ---")
    print(test_code)
    
    secure_code, fixes = generate_secure_patch(test_code)
    
    print("\n--- PATCHED (SECURE) CODE ---")
    print(secure_code)
    print("\n--- APPLIED PATCHES ---")
    for fix in fixes:
        print(f"✔ {fix}")