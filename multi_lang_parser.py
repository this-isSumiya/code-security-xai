import ast
import os
import re

# Dictionary of known unsafe/vulnerable functions across multiple languages
UNSAFE_FUNCTIONS = {
    "python": ["eval", "exec", "pickle.loads", "os.system", "subprocess.call", "input"],
    "c": ["gets", "strcpy", "strcat", "sprintf", "vsprintf", "scanf", "system"],
    "cpp": ["gets", "strcpy", "strcat", "sprintf", "system", "memcpy"],
    "java": ["Runtime.getRuntime().exec", "Statement.executeQuery", "ObjectInputStream", "readObject"],
    "javascript": ["eval", "innerHTML", "outerHTML", "document.write", "setTimeout", "setInterval"],
    "php": ["eval", "exec", "shell_exec", "system", "passthru", "mysql_query", "unserialize"]
}

# Mapping file extensions to programming languages
EXTENSION_MAP = {
    ".py": "python",
    ".c": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".java": "java",
    ".js": "javascript",
    ".ts": "javascript",
    ".php": "php"
}

def detect_language(file_path):
    """Detect programming language based on file extension."""
    _, ext = os.path.splitext(file_path.lower())
    return EXTENSION_MAP.get(ext, "generic")

def check_hardcoded_credentials(code):
    """Scan source code for hardcoded passwords, API keys, or secret tokens."""
    patterns = [
        r'(password|passwd|pwd|secret|api_key|apikey|token|auth_token)\s*=\s*["\'][^"\']+["\']',
        r'(PASSWORD|SECRET_KEY|API_KEY|ACCESS_TOKEN)\s*=\s*["\'][^"\']+["\']'
    ]
    count = 0
    for pattern in patterns:
        matches = re.findall(pattern, code, re.IGNORECASE)
        count += len(matches)
    return 1 if count > 0 else 0

def analyze_python_ast(code):
    """Extract cyclomatic complexity and unsafe function calls using Python AST."""
    tree = ast.parse(code)
    unsafe_count = 0
    complexity = 1  # Base cyclomatic complexity starts at 1

    for node in ast.walk(tree):
        if isinstance(node, (ast.If, ast.For, ast.While, ast.ExceptHandler, ast.With, ast.BoolOp)):
            complexity += 1
        elif isinstance(node, ast.Call):
            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name):
                    func_name = f"{node.func.value.id}.{node.func.attr}"
                else:
                    func_name = node.func.attr
            if func_name in UNSAFE_FUNCTIONS["python"]:
                unsafe_count += 1

    return complexity, unsafe_count

def analyze_generic_language(code, language):
    """Extract control-flow complexity and unsafe function calls for non-Python languages."""
    clean_code = re.sub(r'//.*|/\*[\s\S]*?\*/|#.*', '', code)
    
    branch_keywords = r'\b(if|else\s+if|elif|for|while|case|catch|&&|\|\||\?)\b'
    branches = re.findall(branch_keywords, clean_code)
    complexity = 1 + len(branches)

    unsafe_list = UNSAFE_FUNCTIONS.get(language, [])
    unsafe_count = 0
    for func in unsafe_list:
        pattern = r'\b' + re.escape(func) + r'\s*\('
        matches = re.findall(pattern, clean_code)
        unsafe_count += len(matches)

    return complexity, unsafe_count

def extract_features(file_path):
    """Extract structural and security metrics from any supported source code file."""
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        code = f.read()

    language = detect_language(file_path)
    lines = [line for line in code.splitlines() if line.strip()]
    loc = len(lines)
    hardcoded = check_hardcoded_credentials(code)

    if language == "python":
        try:
            complexity, unsafe_count = analyze_python_ast(code)
        except SyntaxError:
            complexity, unsafe_count = analyze_generic_language(code, "python")
    else:
        complexity, unsafe_count = analyze_generic_language(code, language)

    return {
        "language": language,
        "lines_of_code": loc,
        "cyclomatic_complexity": complexity,
        "unsafe_function_count": unsafe_count,
        "hardcoded_credentials": hardcoded,
        "raw_code": code
    }