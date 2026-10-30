# Checkpoint 6: OpenAPI specification inspection

**This is inventory inspection only, not a live scan.** Uploads are not persisted
or used to configure the fixture scanner. The local backend is unauthenticated;
run it locally and do not expose it publicly.

## What works

- POST a raw UTF-8 OpenAPI 3.0/3.1 YAML or JSON document to `/api/spec/upload`.
  It returns an in-memory inventory with method, path, parameter details,
  authentication requirement and its provenance, input hash and endpoint count.
- Local JSON-pointer references, inherited security and operation-level overrides
  work in the supported subset. Authentication requirements do **not** establish
  ownership, role permissions or authorization to contact a target.
- Input, expansion, parameter, endpoint and serialized-result sizes are bounded.
  Duplicate keys, YAML merges, invalid structures, remote/file references and
  cycles are rejected. No supplied host or `servers` URL is contacted.
- This is not complete OpenAPI validation. Raw multipart forms and compressed
  uploads are not supported. Uploaded parameter metadata may be echoed to the
  caller, so use synthetic or authorized specifications without secrets.
- Existing `/api/endpoints`, `/api/scan`, fixture reports and persisted runs stay
  unchanged. No live account setup, DNS validation, connection pinning or live
  scanning is enabled.

## VS Code judge demonstration

1. Open the repository in VS Code and set up Python 3.11 using
   [the main demo guide](../VS_CODE_DEMO.md). Run:

   ```sh
   python -m pytest -v tests/unit/test_spec_parser.py tests/integration/test_spec_inspection.py
   ```

2. In terminal 1, from the repository root, start the local backend:

   ```sh
   python -m uvicorn canarygate.api.app:app --host 127.0.0.1 --port 8000
   ```

3. In terminal 2, use the bundled **synthetic** spec as the upload. On Linux or
   macOS (or using curl in a shell):

   ```sh
   curl -sS -H 'Content-Type: application/yaml' --data-binary @canarygate/offline/fixture.yaml http://127.0.0.1:8000/api/spec/upload
   ```

   On Windows PowerShell use `curl.exe` instead of `curl`:

   ```powershell
   curl.exe -sS -H "Content-Type: application/yaml" --data-binary "@canarygate/offline/fixture.yaml" http://127.0.0.1:8000/api/spec/upload
   ```

   Show `mode: inventory_only`, `live_scanning: false`, the hash, the endpoint
   count and the expected-access source. The parser reads the file but does not
   send requests to any target.
4. Run `python -m canarygate.demo` in terminal 2. Show that it still runs the
   separate built-in fixture, not the uploaded spec. Open its printed HTML report.
5. Stop the backend with Ctrl+C. For Windows virtual-environment commands, see
   the [main VS Code guide](../VS_CODE_DEMO.md); on Linux, replace `python` with
   `.venv/bin/python` when not activated.

The API response uses a raw body rather than a multipart form and is provisional
pending frontend contract review. See [API draft](../API.md) for limits and errors.
