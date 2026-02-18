import * as vscode from "vscode";

let item: vscode.StatusBarItem | undefined;

export function createStatusBar(context: vscode.ExtensionContext): void {
  item = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    100
  );
  item.command = "workbench.action.problems.focus";
  setClean();
  item.show();
  context.subscriptions.push(item);
  context.subscriptions.push(
    vscode.languages.onDidChangeDiagnostics(refresh)
  );
}

export function setScanning(): void {
  if (!item) { return; }
  item.text = "$(sync~spin) Velka: Scanning\u2026";
  item.tooltip = "Velka is scanning\u2026";
  item.backgroundColor = undefined;
}

export function setClean(): void {
  if (!item) { return; }
  item.text = "$(shield) Velka: Clean";
  item.tooltip = "No secrets detected";
  item.backgroundColor = undefined;
}

export function setError(msg: string): void {
  if (!item) { return; }
  item.text = "$(shield-x) Velka: Error";
  item.tooltip = msg;
  item.backgroundColor = new vscode.ThemeColor("statusBarItem.errorBackground");
}

function refresh(): void {
  if (!item) { return; }
  let errors = 0;
  let warnings = 0;
  for (const [, diags] of vscode.languages.getDiagnostics()) {
    for (const d of diags) {
      if (d.source !== "velka") { continue; }
      if (d.severity === vscode.DiagnosticSeverity.Error) { errors++; }
      else if (d.severity === vscode.DiagnosticSeverity.Warning) { warnings++; }
    }
  }
  const total = errors + warnings;
  if (total === 0) {
    setClean();
    return;
  }
  const parts: string[] = [];
  if (errors > 0)   { parts.push(`${errors} critical`); }
  if (warnings > 0) { parts.push(`${warnings} warnings`); }
  item.text = `$(warning) Velka: ${parts.join(" \u00b7 ")}`;
  item.tooltip = `${total} secret(s) detected \u2014 click to open Problems panel`;
  item.backgroundColor = new vscode.ThemeColor(
    "statusBarItem.warningBackground"
  );
}
