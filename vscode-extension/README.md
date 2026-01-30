# Velka VS Code Extension (MVP)

Run [Velka](https://github.com/wesllen-lima/velka) secret scanner from VS Code.

## Requirements

- [Velka](https://github.com/wesllen-lima/velka) on PATH: `cargo install velka`

## Usage

1. Open Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`)
2. Run **Velka: Scan for secrets**
3. Output appears in the Velka channel

## Development

```bash
cd vscode-extension
npm install
npm run compile
```

Then F5 in VS Code to launch Extension Development Host.

## Publishing to Marketplace

When publishing to the VS Code Marketplace, update `publisher` in `package.json` to your Marketplace publisher ID (e.g. your username or org).
