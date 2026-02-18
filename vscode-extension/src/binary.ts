import * as vscode from "vscode";
import * as path from "path";
import * as fs from "fs";
import * as os from "os";
import { execSync } from "child_process";

export async function resolveBinary(
  context: vscode.ExtensionContext
): Promise<string | null> {
  // 1. User-specified override
  const custom = vscode.workspace
    .getConfiguration("velka")
    .get<string>("binaryPath", "")
    .trim();
  if (custom && fs.existsSync(custom)) {
    return custom;
  }

  // 2. System PATH
  try {
    const cmd = process.platform === "win32" ? "where velka" : "which velka";
    const result = execSync(cmd, { encoding: "utf8", timeout: 3000 })
      .trim()
      .split("\n")[0]
      .trim();
    if (result && fs.existsSync(result)) {
      return result;
    }
  } catch {
    // not in PATH — continue
  }

  // 3. ~/.cargo/bin
  const cargoName = process.platform === "win32" ? "velka.exe" : "velka";
  const cargoBin = path.join(os.homedir(), ".cargo", "bin", cargoName);
  if (fs.existsSync(cargoBin)) {
    return cargoBin;
  }

  // 4. Bundled binary shipped with the extension
  const platform =
    process.platform === "win32"
      ? "win32"
      : process.platform === "darwin"
        ? "darwin"
        : "linux";
  const arch = process.arch === "arm64" ? "arm64" : "x64";
  const ext = process.platform === "win32" ? ".exe" : "";
  const bundled = path.join(
    context.extensionPath,
    "bin",
    `velka-${platform}-${arch}${ext}`
  );
  if (fs.existsSync(bundled)) {
    return bundled;
  }

  return null;
}

export async function promptInstall(): Promise<void> {
  const choice = await vscode.window.showErrorMessage(
    "Velka binary not found. Install it to enable secret scanning.",
    "Install via cargo",
    "Set binary path",
    "Dismiss"
  );

  if (choice === "Install via cargo") {
    const terminal = vscode.window.createTerminal({ name: "Velka Install" });
    terminal.show();
    terminal.sendText("cargo install velka");
  } else if (choice === "Set binary path") {
    const picked = await vscode.window.showOpenDialog({
      canSelectFiles: true,
      canSelectFolders: false,
      openLabel: "Select velka binary",
    });
    if (picked?.[0]) {
      await vscode.workspace
        .getConfiguration("velka")
        .update(
          "binaryPath",
          picked[0].fsPath,
          vscode.ConfigurationTarget.Global
        );
      vscode.window.showInformationMessage(
        "Velka: Binary path saved. Reload the window to apply."
      );
    }
  }
}
