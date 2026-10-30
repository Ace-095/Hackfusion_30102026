"""Authorization matrix view over stored offline runs (spec section 13).

Rows are endpoints; columns are anonymous, own resource, another account's
resource and role. Cells never claim more than was observed: a cell that was not
tested is reported as untested rather than omitted or shown as passing.
"""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

COLUMNS = ("anonymous", "own_resource", "other_account_resource", "role")
_STATE_ORDER = {"hatched": 0, "grey": 1, "green": 2, "orange": 3, "red": 4}
_VERDICT_STATE = {"SAFE": "green", "CONFIRMED": "red", "SUSPECTED": "orange",
                  "INCONCLUSIVE": "hatched", "SKIPPED": "hatched"}
COVERAGE_STATEMENT = ("Partial offline authorization coverage: only cells observed in recorded "
                      "synthetic runs are populated. Untested cells are marked hatched and are not "
                      "evidence of correct behaviour. No live target was contacted.")


def as_run_dict(run):
    """Accept a stored run dict or a validated pydantic run model."""
    if isinstance(run, dict):
        return run
    dump = getattr(run, "model_dump", None)
    if callable(dump):
        return dump(mode="json")
    raise ValueError("a stored run dict or model is required")


def cell_state(verdict):
    return _VERDICT_STATE.get(verdict, "grey")


class MatrixCell(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    column: str
    state: Literal["green", "red", "orange", "grey", "hatched"]
    tested: bool
    verdict: str | None = None
    reason: str
    expected_access: str | None = None
    expected_source: str | None = None
    source_ref: str

    @model_validator(mode="after")
    def coherent_cell(self):
        if self.column not in COLUMNS:
            raise ValueError("unknown matrix column")
        if self.tested is False and (self.state != "hatched" or self.verdict is not None):
            raise ValueError("an untested cell must be hatched and carry no verdict")
        if self.tested is True and self.verdict is None and self.state != "grey":
            raise ValueError("a tested cell without a verdict must be grey (observed only)")
        return self


class MatrixRow(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    endpoint: str
    method: str
    path: str
    expected_access: str | None = None
    expected_source: str | None = None
    cells: list[MatrixCell] = Field(min_length=4, max_length=4)

    @model_validator(mode="after")
    def exact_columns(self):
        if [cell.column for cell in self.cells] != list(COLUMNS):
            raise ValueError("every row must carry exactly the four matrix columns in order")
        return self


class MatrixCoverage(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    scope: Literal["partial_offline"]
    rows: int = Field(ge=0)
    cells: int = Field(ge=0)
    tested: int = Field(ge=0)
    untested: int = Field(ge=0)
    by_state: dict[str, int]
    statement: str
    not_contributing: dict[str, int]

    @model_validator(mode="after")
    def consistent_totals(self):
        if self.tested + self.untested != self.cells or self.rows * len(COLUMNS) != self.cells:
            raise ValueError("matrix coverage totals are inconsistent")
        if sum(self.by_state.values()) != self.cells:
            raise ValueError("matrix state counts are inconsistent")
        return self


class AuthorizationMatrix(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    mode: Literal["offline_authorization_matrix"]
    live_target_contacted: Literal[False]
    network_transport_enabled: Literal[False]
    columns: list[str]
    rows: list[MatrixRow]
    coverage: MatrixCoverage
    verdict_counts: dict[str, int]


def _untested(endpoint, method, path, column, expected_access=None, expected_source=None):
    return {"endpoint": endpoint, "method": method, "path": path, "column": column,
            "verdict": None, "reason": "Not tested in this offline workflow",
            "expected_access": expected_access, "expected_source": expected_source,
            "source_ref": "not_tested"}


def _merge(first, second):
    """Keep the least favourable observation; never let a clean run hide a finding."""
    winner, loser = ((first, second) if _STATE_ORDER[cell_state(first["verdict"])]
                     >= _STATE_ORDER[cell_state(second["verdict"])] else (second, first))
    reasons = [winner["reason"]]
    if loser["reason"] and loser["reason"] != winner["reason"]:
        reasons.append(loser["reason"])
    sources = []
    for item in (winner.get("source_ref"), loser.get("source_ref")):
        if item and item not in sources:
            sources.append(item)
    return {**winner, "reason": " | ".join(reasons), "source_ref": ", ".join(sources)}


def build_matrix(cells, *, not_contributing=None, extra_endpoints=()):
    grouped = {}
    for endpoint in extra_endpoints:
        grouped.setdefault((endpoint["method"], endpoint["path"]), {})
    for cell in cells:
        row_key = (cell["method"], cell["path"])
        columns = grouped.setdefault(row_key, {})
        existing = columns.get(cell["column"])
        columns[cell["column"]] = cell if existing is None else _merge(existing, cell)
    rows = []
    state_counts = {name: 0 for name in _STATE_ORDER}
    tested = untested = 0
    for (method, path), columns in sorted(grouped.items()):
        endpoint = f"{method} {path}"
        inventory = next((item for item in extra_endpoints
                          if item["method"] == method and item["path"] == path), {})
        reference = next(iter(columns.values()), inventory)
        merged = {}
        for column in COLUMNS:
            found = columns.get(column)
            if found is None:
                merged[column] = _untested(endpoint, method, path, column,
                                           reference.get("expected_access"),
                                           reference.get("expected_source"))
            else:
                merged[column] = found
        row_cells = []
        for column in COLUMNS:
            cell = merged[column]
            if cell["verdict"]:
                state = cell_state(cell["verdict"])
            else:
                state = "grey" if cell.get("observed") else "hatched"
            is_tested = bool(cell["verdict"] and cell["verdict"] != "SKIPPED") or bool(cell.get("observed"))
            if is_tested:
                tested += 1
            else:
                untested += 1
            state_counts[state] += 1
            row_cells.append(MatrixCell(
                column=column, state=state, tested=is_tested,
                verdict=cell["verdict"] if is_tested else None,
                reason=cell["reason"], expected_access=cell.get("expected_access"),
                expected_source=cell.get("expected_source"),
                source_ref=cell.get("source_ref") or "unknown"))
        rows.append(MatrixRow(endpoint=endpoint, method=method, path=path,
                              expected_access=reference.get("expected_access"),
                              expected_source=reference.get("expected_source"),
                              cells=row_cells))
    counts = {"CONFIRMED": 0, "SUSPECTED": 0, "SAFE": 0, "INCONCLUSIVE": 0, "SKIPPED": 0}
    for row in rows:
        for cell in row.cells:
            if cell.verdict:
                counts[cell.verdict] += 1
    coverage = MatrixCoverage(scope="partial_offline", rows=len(rows),
                              cells=len(rows) * len(COLUMNS), tested=tested, untested=untested,
                              by_state=state_counts, statement=COVERAGE_STATEMENT,
                              not_contributing=dict(not_contributing or {}))
    return AuthorizationMatrix(mode="offline_authorization_matrix", live_target_contacted=False,
                               network_transport_enabled=False, columns=list(COLUMNS),
                               rows=rows, coverage=coverage, verdict_counts=counts)


def split_endpoint(value, default_method="GET"):
    """Recorded endpoints are stored as "METHOD /path"; never re-parse a path twice."""
    if isinstance(value, str) and " " in value:
        method, path = value.split(" ", 1)
        if method.isalpha() and method.isupper():
            return method, path
    return default_method, value


def _cell(endpoint_method, endpoint_path, column, verdict, reason, expected_access,
          expected_source, source_ref):
    return {"endpoint": f"{endpoint_method} {endpoint_path}", "method": endpoint_method,
            "path": endpoint_path, "column": column, "verdict": verdict, "reason": reason,
            "expected_access": expected_access, "expected_source": expected_source,
            "source_ref": source_ref}


def cells_from_runs(scenario_runs, authentication_runs=(), validation_runs=()):
    """Translate stored offline runs into matrix cells plus coverage notes."""
    cells = []
    notes = {"scenario": len(scenario_runs), "authentication": len(authentication_runs),
             "validation": len(validation_runs)}
    for run in scenario_runs:
        run = as_run_dict(run)
        method, path = split_endpoint(run["recipe"]["detail"])
        ownership = (run.get("evidence") or {}).get("ownership") or {}
        if (ownership.get("checklist") or {}).get("both_owner_baselines") is True:
            cells.append({"endpoint": f"{method} {path}", "method": method, "path": path,
                          "column": "own_resource", "verdict": None, "observed": True,
                          "reason": ("owner baseline observed during ownership verification; "
                                     "no separate policy expectation was recorded"),
                          "expected_access": None, "expected_source": None,
                          "source_ref": f"scenario:{run['scenario_id']}#ownership"})
        cells.append(_cell(method, path, "other_account_resource", run["verdict"], run["reason"],
                           run["policy"]["expected_access"], run["policy"]["expected_source"],
                           f"scenario:{run['scenario_id']}"))
    for run in authentication_runs:
        run = as_run_dict(run)
        for check in run["checks"]:
            evidence = check.get("evidence")
            if not evidence:
                continue
            if check["id"] in {"AUTHN-01", "AUTHN-08"}:
                column = "anonymous"
            elif check["id"] == "AUTHN-04b":
                column = "role"
            else:
                continue
            cells.append(_cell(evidence["method"], evidence["path_template"], column,
                               check["verdict"], check["reason"],
                               "reject unauthenticated requests" if column == "anonymous"
                               else "reject escalated role",
                               "offline authentication scenario policy",
                               f"authentication:{run['scenario_id']}"))
    return cells, notes


def endpoints_from_runs(scenario_runs, authentication_runs=(), validation_runs=()):
    """Every endpoint the stored runs declared, so untested rows stay visible."""
    endpoints = {}
    for run in scenario_runs:
        run = as_run_dict(run)
        for item in run.get("inventory", ()):
            endpoints[(item["method"], item["path"])] = {
                "method": item["method"], "path": item["path"],
                "expected_access": item.get("expected_access"),
                "expected_source": item.get("expected_source")}
    for run in tuple(authentication_runs) + tuple(validation_runs):
        run = as_run_dict(run)
        for operation in run["scope"].get("operations", ()):
            endpoints.setdefault((operation["method"], operation["path"]), {
                "method": operation["method"], "path": operation["path"],
                "expected_access": "declared by the validated scope",
                "expected_source": "validated scope operation"})
    return list(endpoints.values())


def build_authorization_matrix(scenario_runs, authentication_runs=(), validation_runs=()):
    cells, _ = cells_from_runs(scenario_runs, authentication_runs, validation_runs)
    endpoints = endpoints_from_runs(scenario_runs, authentication_runs, validation_runs)
    return build_matrix(cells, not_contributing={"validation_runs": len(validation_runs)},
                        extra_endpoints=endpoints)
