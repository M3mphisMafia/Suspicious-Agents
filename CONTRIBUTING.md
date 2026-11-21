# Contributing

Thanks for helping. Undertow Security is a defensive tool, so every change is judged first on one
question: could it hurt a real user or the app it protects?

## Set up

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[test,aws]'
```

## Before you open a pull request

```bash
.venv/bin/pytest -q
```

```bash
.venv/bin/python -m evals.harness
```

The eval must stay at 0 missed attacks and 0 hard false positives. GitHub runs both on every pull
request.

## Rules of the road

- **Fail closed on attackers, never on users.** A new detector starts as a style signal (it can't
  block alone) until evidence shows it is intent.
- **Keep the model out of the request path.** The LLM judge and flood mode only advise or pick from
  observed values; deterministic code decides what reaches the WAF.
- **Never add real secrets, personal data, IP addresses or account IDs**, including in tests. Use
  the documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and `.example` domains.
- **Infrastructure changes go in the CloudFormation templates**, deployed by the pipeline.
- American spelling. Short code comments. Plain, specific commit messages.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Don't open a public issue for a vulnerability.

By contributing you agree your contribution is licensed under the [Apache License 2.0](LICENSE).
