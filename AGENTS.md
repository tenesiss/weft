# Repository instructions

## Test placement

- Save all automated tests, test helpers, and fixtures under the repository-root `tests/` directory. Do not put `_test.go` files beside production code.
- Mirror the production package path: tests for `protocol/` belong in `tests/protocol/`, and tests for `cmd/demp/` belong in `tests/cmd/demp/`.
- Keep each Go test's original package declaration. Tests may access private package members; do not export application internals just to relocate tests.
- Maintain `tests/overlay.json` when adding, moving, or deleting test Go files. For each file, map its virtual production-package path to its real path under `tests/`, then map that real path to an empty string so Go does not also compile it as a separate package. For example:

  ```json
  "protocol/example_test.go": "tests/protocol/example_test.go",
  "tests/protocol/example_test.go": ""
  ```

## Validation

Run these commands from the repository root; the overlay paths are relative to the working directory:

```sh
go test '-overlay=tests/overlay.json' ./...
go vet '-overlay=tests/overlay.json' ./...
```

Use the overlay for focused tests, coverage, race checks, and fuzzing too, for example `go test '-overlay=tests/overlay.json' -run TestDirectFirst ./routing`. Plain `go test ./...` cannot compile these relocated tests with their production packages. Keep the overlay argument quoted for PowerShell compatibility.

On Windows, if Go is absent from `PATH`, invoke `C:\Program Files\Go\bin\go.exe` explicitly.

```powershell
& 'C:\Program Files\Go\bin\go.exe' test '-overlay=tests/overlay.json' ./...
```
