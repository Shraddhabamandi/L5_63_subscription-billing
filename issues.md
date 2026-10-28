# Static Code Analysis – Issues Found and Fixes

| Issue | Type | Description | Fix Approach |
|---|---|---|---|
| Hardcoded secret | Security | A secret was stored directly in the source code. | Use an environment variable. |
| Unsafe XML parsing | Bandit B405/B314 | Untrusted XML parsing can expose the program to XML attacks. | Use a safer XML parser. |
| Deprecated encryption library | Bandit B413 | The PyCrypto library is deprecated. | Replace it with a maintained encryption library. |
| Poor code formatting | Flake8 | Some lines had formatting problems. | Fix spacing and formatting. |
| Naming and documentation | Pylint | Some functions had naming and documentation issues. | Use snake_case names and add docstrings. |
