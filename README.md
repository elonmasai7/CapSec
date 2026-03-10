# CapSec

CapSec is a lightweight Pact security analyzer. It accepts full Pact modules or snippets and returns a structured JSON report of likely vulnerabilities and unsafe patterns. The current implementation uses heuristic checks designed to simulate the same workflow you will later connect to a real LLM.

## Usage

Analyze a file:

```bash
python -m capsec path/to/contract.pact
```

Analyze from stdin (useful for snippets):

```bash
echo '(defun transfer (from to amount) (update accounts from {"balance": 0}))' | python -m capsec -
```

Analyze a folder of contracts:

```bash
python -m capsec path/to/contracts/
```

Run with an LLM backend (hybrid mode):

```bash
pip install -e .
export CAPSEC_LLM_BACKEND='capsec.anthropic_backend:AnthropicBackend'
export ANTHROPIC_API_KEY='...'
export CAPSEC_LLM_MODEL='claude-3-5-sonnet-latest'
python -m capsec --mode hybrid path/to/contract.pact
```

Run the HTTP API:

```bash
python -m capsec.api --port 8080
```

Example API request:

```bash
curl -X POST localhost:8080/analyze \\
  -H 'Content-Type: application/json' \\
  -d '{"path":"path/to/contracts","mode":"heuristic"}'
```

Run in CI:

```bash
python -m capsec.ci path/to/contracts --fail-on high
```

Human-readable output:

```bash
python -m capsec --format text path/to/contracts/
```

## Output

```json
{
  "contract_name": "snippet",
  "issues": [
    {
      "function_name": "transfer",
      "severity": "High",
      "description": "State-changing logic is present without any explicit authorization checks. Attackers may be able to modify critical state without owning the required capability or guard.",
      "recommendation": "Add a capability or guard check (e.g., `with-capability`, `enforce-keyset`, or `enforce-guard`) before performing state updates.",
      "example_fix": "(defun transfer (...)\n  (with-capability (ADMIN)\n    (update accounts id { balance: (+ balance amount) })))"
    }
  ],
  "summary": {
    "total_issues": 1,
    "critical_issues": 0,
    "recommendation_overview": "Review critical and high findings first, then address authorization and governance gaps."
  }
}
```

## What It Checks (Heuristic Mode)

- State changes without authorization
- State changes before authorization
- Unguarded capabilities
- Unused capabilities
- Hard-coded keysets
- Weak `enforce-one` logic
- Missing authorization in `defpact` steps
- Capability argument mismatches
- Undefined capability usage
- Module governance issues

## Next Step: Plug in a Real LLM

The parser is tolerant of partial inputs. Implement a backend class with `analyze(self, pact_code: str) -> dict` and set `CAPSEC_LLM_BACKEND` to `module:Class`.
