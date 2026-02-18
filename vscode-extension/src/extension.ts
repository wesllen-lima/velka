import * as vscode from "vscode";
import { resolveBinary, promptInstall } from "./binary";
import { startLspClient, stopLspClient } from "./lsp";
import { createStatusBar, setError } from "./statusBar";
import { FindingsProvider } from "./treeView";
import {
  init as initCommands,
  registerAll as registerCommands,
} from "./commands";

export async function activate(
  context: vscode.ExtensionContext
): Promise<void> {
  // Status bar is always visible — show state immediately
  createStatusBar(context);

  // Resolve the velka binary (PATH → cargo → bundled)
  const binaryPath = await resolveBinary(context);
  if (!binaryPath) {
    setError("Binary not found — install velka to enable scanning");
    await promptInstall();
    return;
  }

  // Findings tree view in the Velka activity bar panel
  const provider = new FindingsProvider(context);
  const treeView = vscode.window.createTreeView("velkaFindings", {
    treeDataProvider: provider,
    showCollapseAll: true,
  });
  context.subscriptions.push(treeView);

  // Register all CLI-equivalent commands
  initCommands(binaryPath, provider);
  registerCommands(context);

  // Start the LSP server (`velka lsp`) for real-time inline diagnostics.
  // The LSP handles: textDocument/didOpen, didChange, didSave, didClose.
  try {
    await startLspClient(binaryPath, context);
  } catch (err) {
    setError(`LSP failed to start: ${err}`);
    vscode.window.showWarningMessage(
      `Velka: LSP server failed to start. Inline diagnostics unavailable. ${err}`
    );
  }
}

export async function deactivate(): Promise<void> {
  await stopLspClient();
}
