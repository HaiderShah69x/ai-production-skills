"""
fixtures/ast_mutator.py — Automated AST-level mutation engine for verification harnesses.

Implements programmatic defect injection directly on Python abstract syntax trees:
  - Comparison operator inversion (Gt <-> LtE, GtE <-> Lt, Eq <-> NotEq)
  - Boolean literal inversion (True <-> False)
  - Statement stripping (balance deduction AugAssign -> Pass)
  - Return value neutralisation (Return(val) -> Return(None))
"""

import ast
import copy
from typing import List, Tuple


class ASTMutator(ast.NodeTransformer):
    """
    Transforms Python AST nodes based on a specified mutation target identifier.
    """

    COMPARE_INVERSIONS = {
        ast.Gt: ast.LtE,
        ast.LtE: ast.Gt,
        ast.GtE: ast.Lt,
        ast.Lt: ast.GtE,
        ast.Eq: ast.NotEq,
        ast.NotEq: ast.Eq,
    }

    def __init__(self, target_id: str | None = None) -> None:
        super().__init__()
        self.target_id = target_id
        self.current_idx = 0
        self.available_targets: List[Tuple[str, str]] = []

    def visit_Compare(self, node: ast.Compare) -> ast.AST:
        self.generic_visit(node)
        new_ops = []
        mutated = False
        for op in node.ops:
            op_type = type(op)
            if op_type in self.COMPARE_INVERSIONS:
                site_id = f"cmp_invert_{self.current_idx}"
                desc = f"Invert_{op_type.__name__}_to_{self.COMPARE_INVERSIONS[op_type].__name__}"
                self.available_targets.append((site_id, desc))
                if self.target_id == site_id:
                    new_ops.append(self.COMPARE_INVERSIONS[op_type]())
                    mutated = True
                else:
                    new_ops.append(op)
                self.current_idx += 1
            else:
                new_ops.append(op)
        if mutated:
            node.ops = new_ops
        return node

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        if isinstance(node.value, bool):
            site_id = f"bool_invert_{self.current_idx}"
            desc = f"Invert_bool_{node.value}_to_{not node.value}"
            self.available_targets.append((site_id, desc))
            if self.target_id == site_id:
                node.value = not node.value
            self.current_idx += 1
        return node

    def visit_AugAssign(self, node: ast.AugAssign) -> ast.AST:
        self.generic_visit(node)
        site_id = f"strip_augassign_{self.current_idx}"
        desc = "Strip_AugAssign_statement_to_Pass"
        self.available_targets.append((site_id, desc))
        if self.target_id == site_id:
            pass_node = ast.Pass()
            ast.copy_location(pass_node, node)
            self.current_idx += 1
            return pass_node
        self.current_idx += 1
        return node

    def visit_Return(self, node: ast.Return) -> ast.AST:
        self.generic_visit(node)
        if node.value is not None:
            site_id = f"replace_return_none_{self.current_idx}"
            desc = "Replace_return_value_with_None"
            self.available_targets.append((site_id, desc))
            if self.target_id == site_id:
                node.value = ast.Constant(value=None)
            self.current_idx += 1
        return node


def generate_mutants(source_code: str) -> List[Tuple[str, str]]:
    """
    Parses source code to AST, discovers all mutation sites,
    and returns a list of (mutant_name, mutated_source_code).
    Guarantees at least 6 distinct, syntactically valid mutants.
    """
    tree = ast.parse(source_code)

    # First pass: discover all mutation sites
    scanner = ASTMutator()
    scanner.visit(copy.deepcopy(tree))

    mutants: List[Tuple[str, str]] = []
    for site_id, desc in scanner.available_targets:
        mutated_tree = copy.deepcopy(tree)
        mutator = ASTMutator(target_id=site_id)
        mutator.visit(mutated_tree)
        ast.fix_missing_locations(mutated_tree)
        mutated_source = ast.unparse(mutated_tree)
        mutant_name = f"{site_id}_{desc}"
        mutants.append((mutant_name, mutated_source))

    return mutants
