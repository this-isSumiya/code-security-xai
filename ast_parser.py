import ast

class VulnerabilityMetricsExtractor(ast.NodeVisitor):
    def __init__(self):
        self.unsafe_functions_count = 0
        self.missing_input_validation = 0
        self.hardcoded_credentials = 0
        self.cyclomatic_complexity = 1
        
        self.unsafe_funcs = {'eval', 'exec', 'input', 'os.system', 'subprocess.run'}
        self.sensitive_keywords = {'password', 'secret', 'api_key', 'token', 'auth'}

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name):
            if node.func.id in self.unsafe_funcs:
                self.unsafe_functions_count += 1
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.attr in {'system', 'popen'}:
                self.unsafe_functions_count += 1
        if isinstance(node.func, ast.Name) and node.func.id == 'input':
            self.missing_input_validation += 1
        self.generic_visit(node)

    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                if any(keyword in var_name for keyword in self.sensitive_keywords):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        self.hardcoded_credentials += 1
        self.generic_visit(node)

    def visit_If(self, node):
        self.cyclomatic_complexity += 1
        self.generic_visit(node)

    def visit_While(self, node):
        self.cyclomatic_complexity += 1
        self.generic_visit(node)

    def visit_For(self, node):
        self.cyclomatic_complexity += 1
        self.generic_visit(node)

def extract_code_metrics(source_code):
    tree = ast.parse(source_code)
    extractor = VulnerabilityMetricsExtractor()
    extractor.visit(tree)
    return {
        'unsafe_functions_count': extractor.unsafe_functions_count,
        'missing_input_validation': extractor.missing_input_validation,
        'hardcoded_credentials': extractor.hardcoded_credentials,
        'cyclomatic_complexity': extractor.cyclomatic_complexity
    }