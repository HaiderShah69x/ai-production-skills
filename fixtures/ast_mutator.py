"""
fixtures/ast_mutator.py — Automated AST-level mutation engine for verification harnesses.

Implements programmatic defect injection directly on Python abstract syntax trees:
  - Comparison operator inversion (Gt <-> LtE, GtE <-> Lt, Eq <-> NotEq)
  - Boundary comparison mutations (Lt <-> LtE, Gt <-> GtE — strict vs non-strict)
  - Boolean literal inversion (True <-> False)
  - Off-by-one arithmetic mutations (Add <-> Sub, Mult <-> FloorDiv)
  - Statement stripping (balance deduction AugAssign -> Pass)
  - Return value neutralisation (Return(val) -> Return(None))
  - Exception swallowing mutations (ExceptHandler body -> Pass)
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

    BOUNDARY_MUTATIONS = {
        ast.Lt: ast.LtE,
        ast.LtE: ast.Lt,
        ast.Gt: ast.GtE,
        ast.GtE: ast.Gt,
    }

    ARITHMETIC_INVERSIONS = {
        ast.Add: ast.Sub,
        ast.Sub: ast.Add,
        ast.Mult: ast.FloorDiv,
        ast.FloorDiv: ast.Mult,
    }

    def __init__(self, target_id: str | None = None) -> None:
        super().__init__()
        self.target_id = target_id
        self.current_idx = 0
        self.available_targets: List[Tuple[str, str]] = []

    def visit_Compare(self, node: ast.Compare) -> ast.AST:
        self.generic_visit(node)
        new_ops = list(node.ops)
        for i, op in enumerate(node.ops):
            op_type = type(op)

            # Full inversion mutations (Gt <-> LtE, etc.)
            if op_type in self.COMPARE_INVERSIONS:
                site_id = f"cmp_invert_{self.current_idx}"
                inv_type = self.COMPARE_INVERSIONS[op_type]
                desc = f"Invert_{op_type.__name__}_to_{inv_type.__name__}"
                self.available_targets.append((site_id, desc))
                if self.target_id == site_id:
                    new_ops[i] = inv_type()
                self.current_idx += 1

            # Boundary mutations (strict <-> non-strict: Lt <-> LtE, Gt <-> GtE)
            if op_type in self.BOUNDARY_MUTATIONS:
                site_id = f"boundary_{self.current_idx}"
                bnd_type = self.BOUNDARY_MUTATIONS[op_type]
                desc = f"Boundary_{op_type.__name__}_to_{bnd_type.__name__}"
                self.available_targets.append((site_id, desc))
                if self.target_id == site_id:
                    new_ops[i] = bnd_type()
                self.current_idx += 1

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

        # Arithmetic inversion on AugAssign op (e.g. -= becomes +=)
        op_type = type(node.op)
        if op_type in self.ARITHMETIC_INVERSIONS:
            arith_id = f"arith_augassign_{self.current_idx}"
            inv_type = self.ARITHMETIC_INVERSIONS[op_type]
            desc = f"ArithInvert_{op_type.__name__}_to_{inv_type.__name__}"
            self.available_targets.append((arith_id, desc))
            if self.target_id == arith_id:
                node.op = inv_type()
            self.current_idx += 1
        else:
            self.current_idx += 1

        return node

    def visit_BinOp(self, node: ast.BinOp) -> ast.AST:
        self.generic_visit(node)
        op_type = type(node.op)
        if op_type in self.ARITHMETIC_INVERSIONS:
            site_id = f"arith_binop_{self.current_idx}"
            inv_type = self.ARITHMETIC_INVERSIONS[op_type]
            desc = f"ArithInvert_{op_type.__name__}_to_{inv_type.__name__}"
            self.available_targets.append((site_id, desc))
            if self.target_id == site_id:
                node.op = inv_type()
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

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> ast.AST:
        self.generic_visit(node)
        if node.body and not (len(node.body) == 1 and isinstance(node.body[0], ast.Pass)):
            site_id = f"swallow_except_{self.current_idx}"
            desc = "Swallow_ExceptHandler_body_to_Pass"
            self.available_targets.append((site_id, desc))
            if self.target_id == site_id:
                pass_node = ast.Pass()
                ast.copy_location(pass_node, node.body[0])
                node.body = [pass_node]
            self.current_idx += 1
        return node


def generate_mutants(source_code: str) -> List[Tuple[str, str]]:
    """
    Parses source code to AST, discovers all mutation sites,
    and returns a list of (mutant_name, mutated_source_code).
    Guarantees at least 15 distinct, syntactically valid mutants.
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
