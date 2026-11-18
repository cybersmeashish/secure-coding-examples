# Application security: object authorization lab

An inspectable example of how an order identifier becomes a cross-tenant data-access bug, and how a server-side authorization decision changes the result.

**Status:** synthetic Python reference lab. No application deployment or real vulnerability disclosure is claimed.

## Business decision

Can a customer or support operator access this specific order? A valid identifier and a role name are not enough. The decision also needs trusted authentication, tenant binding, and object ownership or a scoped support permission.

## Inspect and reproduce

```bash
git clone https://github.com/cybersmeashish/secure-coding-examples.git
cd secure-coding-examples
python3 -m unittest discover -s tests -v
```

Python 3.10 or later. No external packages, account, target, or network service is required.

| Artifact | What to inspect |
| --- | --- |
| [authorization.py](authorization.py) | Vulnerable ID-only lookup and the protected read path |
| [Regression cases](tests/test_authorization.py) | Own order, another owner, another tenant, support scope, unverified claims, missing context, and missing objects |
| [Verification record](docs/verification.md) | Local test conditions and limitations |

## Trust boundary

`Principal` represents identity and roles supplied by a trusted server-side authentication layer. The `authenticated` fixture flag does not verify a token. A production integration must construct this context from verified authentication, rather than bind these fields from a customer request or model output.

The example uses in-memory synthetic data. It does not demonstrate database isolation, token validation, distributed policy enforcement, or production tenancy.

## Research connection

This control belongs in the [Sentinel Logistics asset and action map](https://github.com/cybersmeashish/Ashish-research/blob/main/weeks/01-system-and-asset-inventory/scope-and-evidence.md). The same trusted context must survive application, retrieval, and agent-tool boundaries.

[Security portfolio](https://github.com/cybersmeashish) · [Research and framework notes](https://github.com/cybersmeashish/Ashish-research)
