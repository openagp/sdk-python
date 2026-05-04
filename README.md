# openagp/sdk-python

**Reference Python SDK for AGP — vendor-side and plane-side.**

## Status

Scaffold. Implementation tracked in [§4.2 Phase 1](https://github.com/openagp/spec/blob/main/concept-and-spec.md#42-build-order--what-claude-code-should-build-first) of the spec.

## Planned API

```python
from openagp.events import Event, sign, verify
from openagp.policy import Policy, evaluate
from openagp.server import vendor_app, plane_app   # FastAPI scaffolds
from openagp.client import VendorClient, PlaneClient
```

Cross-language interop is verified in CI: events emitted by this SDK are verified by [`openagp/sdk-typescript`](https://github.com/openagp/sdk-typescript), and vice versa.

## Install

```bash
pip install openagp
```

*(Stub package reserves the name on PyPI; functional release pending Phase 1.)*

## Python support

3.10+

## License

[Apache-2.0](LICENSE).
