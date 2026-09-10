# Contributing to SolSOC

Thanks for your interest in improving SolSOC. Contributions are welcome — bug reports, feature suggestions, documentation improvements, and code fixes.

## Before you start

By submitting any contribution to this repository, you agree to the **Contributor License Agreement (CLA)** included in the [`LICENSE`](./LICENSE) file. In short: your contribution becomes part of SolSOC and the author retains the right to modify, distribute, or relicense it. You confirm the contribution is your original work.

## How to contribute

### Report a bug

Open an issue with:
- A clear description of the problem
- Steps to reproduce it
- What you expected vs. what actually happened
- Your OS, Python version, and which LLM provider you were using

### Suggest a feature

Open an issue describing:
- The problem you're trying to solve
- Your proposed solution
- Any alternatives you considered

Feature suggestions are reviewed and prioritized by the author. Opening an issue first (before a PR) avoids wasted effort if the direction doesn't fit the roadmap.

### Submit a pull request

1. Fork the repo and create a branch from `main`.
2. Make your changes — keep the scope focused (one fix or feature per PR).
3. Add or update tests to cover your change.
4. Confirm all tests pass: `pytest tests/ -v`
5. Open a PR with a clear title and description of what changed and why.

PRs are reviewed by the author. Accepted contributions may be modified before merging. Not all PRs will be merged — if you want to confirm interest before investing time, open an issue first.

## Development setup

```bash
git clone https://github.com/luis-troccoli/solsoc.git
cd solsoc
pip install -e ".[dev]"
pytest tests/
```

## Code style

- Follow the existing patterns in the codebase.
- Keep functions small and focused.
- Add docstrings to public functions and classes.
- No external dependencies beyond what's already in `pyproject.toml` without discussion first.

## Questions

Open an issue or reach out at ltrocc@gmail.com.
