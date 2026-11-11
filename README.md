# luvmacro-scanner

Virus scanning for the [LuvMacro Marketplace](https://rowen.work/luvmacro/marketplace), on GitHub's free runners.

Every few minutes `.github/workflows/scan.yml` starts ClamAV (with freshly downloaded signatures), asks the marketplace
for files waiting to be scanned, scans them, reports the results and stops. Nothing is stored between runs.

- `scanner.js` talks only to `https://rowen.work/api/luvmacro-market-scan`, with signed, single-use requests.
- The one secret, `LUVMACRO_SCANNER_SECRET`, is a repository secret: GitHub never shows it in this public repository or its logs.
- It never runs a macro. It only reads bytes and asks ClamAV about them.

Source of truth: `tools/luvmacro-scanner/` in the website repository. Update both together.
