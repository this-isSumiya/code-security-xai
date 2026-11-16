import re

# Language-specific secure code replacement rules
PATCH_RULES = {
    "python": [
        (r'\beval\s*\(', 'ast.literal_eval(', "Replaced unsafe eval() with ast.literal_eval()"),
        (r'\bexec\s*\(', '# [SECURITY PATCH] Removed unsafe exec(): ', "Disabled unsafe exec() execution"),
        (r'\bos\.system\s*\(', 'subprocess.run(', "Replaced os.system() with safer subprocess.run()")
    ],
    "c": [
        (r'\bgets\s*\(([^)]+)\)', r'fgets(\1, sizeof(\1), stdin)', "Replaced buffer-overflow prone gets() with fgets()"),
        (r'\bstrcpy\s*\(([^,]+),\s*([^)]+)\)', r'strncpy(\1, \2, sizeof(\1) - 1)', "Replaced unsafe strcpy() with bounded strncpy()"),
        (r'\bsprintf\s*\(([^,]+),', r'snprintf(\1, sizeof(\1),', "Replaced sprintf() with safer snprintf()")
    ],
    "cpp": [
        (r'\bgets\s*\(([^)]+)\)', r'fgets(\1, sizeof(\1), stdin)', "Replaced buffer-overflow prone gets() with fgets()"),
        (r'\bstrcpy\s*\(([^,]+),\s*([^)]+)\)', r'strncpy(\1, \2, sizeof(\1) - 1)', "Replaced unsafe strcpy() with bounded strncpy()")
    ],
    "javascript": [
        (r'\beval\s*\(', 'JSON.parse(', "Replaced unsafe eval() with JSON.parse()"),
        (r'\.innerHTML\s*=', '.textContent =', "Replaced XSS-prone innerHTML with safe textContent"),
        (r'\bdocument\.write\s*\(', 'console.log(', "Replaced unsafe document.write() with console.log()")
    ],
    "java": [
        (r'Statement\s+(\w+)\s*=', r'PreparedStatement \1 =', "Suggested PreparedStatement to prevent SQL Injection")
    ],
    "php": [
        (r'\bmysql_query\s*\(', 'mysqli_prepare(', "Replaced deprecated mysql_query() with mysqli_prepare()"),
        (r'\beval\s*\(', '// [SECURITY PATCH] Disabled eval(): ', "Disabled unsafe eval() in PHP")
    ]
}

def generate_secure_patch(code, language):
    """Automatically generate secure code patches for detected vulnerabilities."""
    patched_code = code
    applied_fixes = []

    # 1. Apply language-specific unsafe function replacements
    rules = PATCH_RULES.get(language, [])
    for pattern, replacement, description in rules:
        if re.search(pattern, patched_code):
            patched_code = re.sub(pattern, replacement, patched_code)
            applied_fixes.append(description)

    # 2. Remediate hardcoded credentials across all languages
    secret_pattern = r'((?:password|passwd|pwd|secret|api_key|apikey|token)\s*=\s*)["\'][^"\']+["\']'
    if re.search(secret_pattern, patched_code, re.IGNORECASE):
        patched_code = re.sub(
            secret_pattern,
            r'\1os.getenv("SECRET_CREDENTIAL") /* Moved secret to Environment Variable */',
            patched_code,
            flags=re.IGNORECASE
        )
        applied_fixes.append("Replaced hardcoded credentials with environment variable reference")

    return patched_code, applied_fixes