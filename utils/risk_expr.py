import ast
import re
from functools import lru_cache
from typing import Any

from sqlalchemy.orm import Session

from database import RiskRule


MAX_EXPRESSION_LENGTH = 512
MAX_AST_NODES = 256
MAX_AST_DEPTH = 16


def _count_nodes_and_depth(node: ast.AST, depth: int = 1) -> tuple[int, int]:
    total_nodes = 1
    max_depth = depth
    for child in ast.iter_child_nodes(node):
        child_nodes, child_depth = _count_nodes_and_depth(child, depth + 1)
        total_nodes += child_nodes
        if child_depth > max_depth:
            max_depth = child_depth
    return total_nodes, max_depth


def _validate_ast_complexity(tree: ast.AST) -> None:
    node_count, depth = _count_nodes_and_depth(tree)
    if node_count > MAX_AST_NODES:
        raise ValueError("expression too complex: too many AST nodes")
    if depth > MAX_AST_DEPTH:
        raise ValueError("expression too complex: AST depth exceeded")


@lru_cache(maxsize=512)
def _parse_expression_cached(expression: str) -> ast.Expression:
    expr = (expression or "").strip()
    if len(expr) > MAX_EXPRESSION_LENGTH:
        raise ValueError("expression too long")
    parsed = ast.parse(expr, mode="eval")
    _validate_ast_complexity(parsed)
    return parsed


class _ExprEvaluator:
    def __init__(self, context: dict[str, Any]):
        self.context = context
        self.allowed_identifiers = set(context.keys()) | {"True", "False", "None"}
        self.allowed_funcs = {
            "contains": self._contains,
            "startswith": self._startswith,
            "endswith": self._endswith,
            "regex": self._regex,
            "lower": self._lower,
            "upper": self._upper,
            "len": self._len,
        }

    def evaluate(self, expression: str) -> bool:
        parsed = _parse_expression_cached(expression)
        result = self._eval_node(parsed.body)
        return bool(result)

    def _eval_node(self, node: ast.AST) -> Any:
        if isinstance(node, ast.BoolOp):
            values = [bool(self._eval_node(v)) for v in node.values]
            if isinstance(node.op, ast.And):
                return all(values)
            if isinstance(node.op, ast.Or):
                return any(values)
            raise ValueError("unsupported bool operator")

        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return not bool(self._eval_node(node.operand))

        if isinstance(node, ast.Compare):
            left = self._eval_node(node.left)
            for op, comparator in zip(node.ops, node.comparators):
                right = self._eval_node(comparator)
                if isinstance(op, ast.Eq):
                    matched = left == right
                elif isinstance(op, ast.NotEq):
                    matched = left != right
                elif isinstance(op, ast.In):
                    matched = left in right
                elif isinstance(op, ast.NotIn):
                    matched = left not in right
                elif isinstance(op, ast.Gt):
                    matched = left > right
                elif isinstance(op, ast.GtE):
                    matched = left >= right
                elif isinstance(op, ast.Lt):
                    matched = left < right
                elif isinstance(op, ast.LtE):
                    matched = left <= right
                else:
                    raise ValueError("unsupported comparator")
                if not matched:
                    return False
                left = right
            return True

        if isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name):
                raise ValueError("unsupported function call")
            func_name = node.func.id
            func = self.allowed_funcs.get(func_name)
            if not func:
                raise ValueError(f"unsupported function: {func_name}")
            args = [self._eval_node(arg) for arg in node.args]
            return func(*args)

        if isinstance(node, ast.Name):
            if node.id in {"True", "False", "None"}:
                return {"True": True, "False": False, "None": None}[node.id]
            if node.id not in self.allowed_identifiers:
                raise ValueError(f"unknown identifier: {node.id}")
            return self.context.get(node.id)

        if isinstance(node, ast.Attribute):
            base = self._eval_node(node.value)
            if isinstance(base, dict):
                return base.get(node.attr)
            return getattr(base, node.attr, None)

        if isinstance(node, ast.Constant):
            return node.value

        if isinstance(node, ast.List):
            return [self._eval_node(elt) for elt in node.elts]

        if isinstance(node, ast.Tuple):
            return tuple(self._eval_node(elt) for elt in node.elts)

        if isinstance(node, ast.Set):
            return {self._eval_node(elt) for elt in node.elts}

        raise ValueError(f"unsupported expression node: {type(node).__name__}")

    @staticmethod
    def _contains(text: Any, needle: Any) -> bool:
        return str(needle) in str(text or "")

    @staticmethod
    def _startswith(text: Any, prefix: Any) -> bool:
        return str(text or "").startswith(str(prefix))

    @staticmethod
    def _endswith(text: Any, suffix: Any) -> bool:
        return str(text or "").endswith(str(suffix))

    @staticmethod
    def _regex(text: Any, pattern: Any) -> bool:
        return re.search(str(pattern), str(text or "")) is not None

    @staticmethod
    def _lower(text: Any) -> str:
        return str(text or "").lower()

    @staticmethod
    def _upper(text: Any) -> str:
        return str(text or "").upper()

    @staticmethod
    def _len(value: Any) -> int:
        if value is None:
            return 0
        return len(value)


def build_risk_context(**kwargs: Any) -> dict[str, Any]:
    context = {
        "username": kwargs.get("username", ""),
        "ip": kwargs.get("ip", ""),
        "path": kwargs.get("path", ""),
        "user_agent": kwargs.get("user_agent", ""),
        "browser": kwargs.get("browser", ""),
        "os": kwargs.get("os", ""),
        "location": kwargs.get("location", ""),
        "is_mobile": bool(kwargs.get("is_mobile", False)),
        "fail_count": int(kwargs.get("fail_count", 0) or 0),
    }
    context["req"] = {
        "username": context["username"],
        "ip": context["ip"],
        "path": context["path"],
        "user_agent": context["user_agent"],
        "browser": context["browser"],
        "os": context["os"],
        "location": context["location"],
        "is_mobile": context["is_mobile"],
        "fail_count": context["fail_count"],
    }
    return context


def evaluate_match_expression(expression: str, context: dict[str, Any]) -> bool:
    expr = (expression or "").strip()
    if not expr:
        return True
    evaluator = _ExprEvaluator(context)
    return evaluator.evaluate(expr)


def validate_match_expression(expression: str) -> tuple[bool, str | None]:
    expr = (expression or "").strip()
    if not expr:
        return False, "match_key 不能为空"
    try:
        _ExprEvaluator(build_risk_context()).evaluate(expr)
        return True, None
    except Exception as exc:
        return False, str(exc)


def resolve_login_fail_policy(
        db: Session,
        context: dict[str, Any],
        default_threshold: int,
        default_window: int,
        rule_type: str = "LOGIN_FAIL_CAPTCHA",
        action: str = "CAPTCHA"
) -> tuple[int, int, int | None]:
    rules = db.query(RiskRule).filter(
        RiskRule.rule_type == rule_type,
        RiskRule.status.is_(True),
        RiskRule.action == action
    ).order_by(RiskRule.id.desc()).all()

    for rule in rules:
        expr = (rule.match_key or "").strip()
        try:
            if evaluate_match_expression(expr, context):
                threshold = int(rule.threshold_count or default_threshold)
                window = int(rule.threshold_window or default_window)
                return threshold, window, int(getattr(rule, "id", 0))
        except Exception:
            continue

    return int(default_threshold), int(default_window), None

