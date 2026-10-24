# npv-v2ray-extractor

[![Launch Web App](https://img.shields.io/badge/Launch%20Web%20App-theneet0.github.io%2Fnpv--v2ray--extractor-000000?style=for-the-badge&logo=googlechrome&logoColor=white)](https://theneet0.github.io/npv-v2ray-extractor/)

Extractor and converter for NPV V2Ray export formats (`.npvt`, `.npvs` v5).

Runs client-side in the browser.

## Usage

### Web
Open **[theneet0.github.io/npv-v2ray-extractor](https://theneet0.github.io/npv-v2ray-extractor/)** (or open `index.html` locally).

1. Select or drop an `.npvt` or `.npvs` file.
2. If encrypted, enter the passphrase or load the matching P-256 private key (`.json` / `.pem`).
3. View, copy, or download the extracted V2Ray configurations.

## Build

```bash
npm install
npm run build
```

Compiled standalone HTML is written to `index.html` and `dist/NPV-V2Ray-Extractor-v2.5.0.html`.

## License

[AGPL-3.0](LICENSE)
