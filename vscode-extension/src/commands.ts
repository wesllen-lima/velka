import * as vscode from "vscode";
import * as path from "path";
import * as fs from "fs";
import { execFile } from "child_process";
import { promisify } from "util";
import { FindingsProvider } from "./treeView";

const execFileAsync = promisify(execFile);

let _bin = "velka";
let _provider: FindingsProvider;

export function init(binaryPath: string, provider: FindingsProvider): void {
  _bin = binaryPath;
  _provider = provider;
}

function getWorkspaceRoot(): string | undefined {
  return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
}

async function runVelka(
  args: string[],
  cwd: string,
  channel: vscode.OutputChannel
): Promise<void> {
  channel.clear();
  channel.show(true);
  channel.appendLine(`> velka ${args.join(" ")}\n`);
  try {
    const { stdout, stderr } = await execFileAsync(_bin, args, {
      cwd,
      maxBuffer: 20 * 1024 * 1024,
    });
    if (stdout) { channel.append(stdout); }
    if (stderr) { channel.append(stderr); }
  } catch (err: unknown) {
    const e = err as { stdout?: string; stderr?: string; code?: number };
    if (e.stdout) { channel.append(e.stdout); }
    if (e.stderr) { channel.append(e.stderr); }
    // exit code 1 = findings detected (not an error)
    if ((e.code ?? 0) !== 1) {
      channel.appendLine(`\nError running velka: ${err}`);
    }
  }
}

export function registerAll(context: vscode.ExtensionContext): void {
  const channel = vscode.window.createOutputChannel("Velka");
  context.subscriptions.push(channel);

  const cfg = () => vscode.workspace.getConfiguration("velka");

  const reg = (id: string, fn: () => Promise<void>): void => {
    context.subscriptions.push(vscode.commands.registerCommand(id, fn));
  };

  // ── Scan ─────────────────────────────────────────────────────────────────

  reg("velka.scan", async () => {
    const cwd = getWorkspaceRoot();
    if (!cwd) { return; }
    const args = ["scan", "."];
    if (cfg().get<boolean>("verifyLiveSecrets")) { args.push("--verify"); }
    if (cfg().get<boolean>("godMode"))           { args.push("--god-mode"); }
    await runVelka(args, cwd, channel);
    _provider.refresh();
  });

  reg("velka.scanFile", async () => {
    const file = vscode.window.activeTextEditor?.document.uri.fsPath;
    if (!file) { return; }
    const cwd = getWorkspaceRoot() ?? path.dirname(file);
    await runVelka(["scan", file], cwd, channel);
  });

  reg("velka.scanDiff", async () => {
    const cwd = getWorkspaceRoot();
    if (!cwd) { return; }
    await runVelka(["scan", ".", "--diff"], cwd, channel);
    _provider.refresh();
  });

  reg("velka.scanStaged", async () => {
    const cwd = getWorkspaceRoot();
    if (!cwd) { return; }
    await runVelka(["scan", ".", "--staged"], cwd, channel);
    _provider.refresh();
  });

  reg("velka.scanGitHistory", async () => {
    const cwd = getWorkspaceRoot();
    if (!cwd) { return; }
    await runVelka(["scan", ".", "--deep-scan"], cwd, channel);
    _provider.refresh();
  });

  reg("velka.scanGodMode", async () => {
    const cwd = getWorkspaceRoot();
    if (!cwd) { return; }
    await runVelka(["scan", ".", "--god-mode", "--verify"], cwd, channel);
    _provider.refresh();
  });

  reg("velka.exportSarif", async () => {
    const cwd = getWorkspaceRoot();
    if (!cwd) { return; }
    const outPath = path.join(cwd, "velka-results.sarif");
    channel.clear();
    channel.show(true);
    channel.appendLine("> velka scan . --format sarif\n");
    try {
      const { stdout } = await execFileAsync(
        _bin,
        ["scan", ".", "--format", "sarif"],
        { cwd, maxBuffer: 20 * 1024 * 1024 }
      );
      fs.writeFileSync(outPath, stdout, "utf8");
      const doc = await vscode.workspace.openTextDocument(outPath);
      await vscode.window.showTextDocument(doc);
      vscode.window.showInformationMessage(`SARIF saved: ${outPath}`);
    } catch (err: unknown) {
      const e = err as { stdout?: string; stderr?: string };
      if (e.stdout) { channel.append(e.stdout); }
      if (e.stderr) { channel.append(e.stderr); }
      channel.appendLine(`\nError: ${err}`);
    }
  });

  // ── Setup ─────────────────────────────────────────────────────────────────

  reg("velka.init", async () => {
    const cwd = getWorkspaceRoot();
    if (!cwd) { return; }
    const preset = await vscode.window.showQuickPick(
      ["balanced", "strict", "ci", "monorepo"],
      { placeHolder: "Select configuration preset" }
    );
    if (!preset) { return; }
    await runVelka(["init", "--preset", preset], cwd, channel);
  });

  reg("velka.hookInstall", async () => {
    const cwd = getWorkspaceRoot();
    if (!cwd) { return; }
    const mode = await vscode.window.showQuickPick(
      [
        { label: "Normal", description: "Block mortal sins (high confidence)" },
        { label: "Strict", description: "Block all findings including venial sins" },
      ],
      { placeHolder: "Select pre-commit hook mode" }
    );
    if (!mode) { return; }
    const args = ["hook", "install"];
    if (mode.label === "Strict") { args.push("--strict"); }
    await runVelka(args, cwd, channel);
  });

  // ── Baseline ──────────────────────────────────────────────────────────────

  reg("velka.baselineSave", async () => {
    const cwd = getWorkspaceRoot();
    if (!cwd) { return; }
    const ok = await vscode.window.showWarningMessage(
      "Save current findings as baseline? Existing baseline will be overwritten.",
      "Save",
      "Cancel"
    );
    if (ok !== "Save") { return; }
    await runVelka(["baseline", "save", "."], cwd, channel);
  });

  reg("velka.baselineDiff", async () => {
    const cwd = getWorkspaceRoot();
    if (!cwd) { return; }
    await runVelka(["baseline", "diff", "."], cwd, channel);
  });

  reg("velka.baselineShow", async () => {
    const cwd = getWorkspaceRoot();
    if (!cwd) { return; }
    await runVelka(["baseline", "show"], cwd, channel);
  });

  // ── Remediation ───────────────────────────────────────────────────────────

  reg("velka.rotate", async () => {
    const cwd = getWorkspaceRoot();
    if (!cwd) { return; }
    await runVelka(["rotate", ".", "--commands"], cwd, channel);
  });

  reg("velka.honeytokenGenerate", async () => {
    const cwd = getWorkspaceRoot();
    if (!cwd) { return; }
    await runVelka(["honeytoken", "generate"], cwd, channel);
  });

  // ── Rules ─────────────────────────────────────────────────────────────────

  reg("velka.rulesList", async () => {
    const cwd = getWorkspaceRoot();
    if (!cwd) { return; }
    await runVelka(["rules", "list"], cwd, channel);
  });

  reg("velka.rulesInstall", async () => {
    const cwd = getWorkspaceRoot();
    if (!cwd) { return; }
    const src = await vscode.window.showInputBox({
      prompt: "URL or local path to rules file (.toml or .yaml)",
      placeHolder: "https://example.com/rules.toml",
    });
    if (!src) { return; }
    await runVelka(["rules", "install", src], cwd, channel);
  });

  // ── Quarantine ────────────────────────────────────────────────────────────

  reg("velka.quarantineList", async () => {
    const cwd = getWorkspaceRoot();
    if (!cwd) { return; }
    await runVelka(["quarantine", "list"], cwd, channel);
  });

  reg("velka.quarantineRestore", async () => {
    const cwd = getWorkspaceRoot();
    if (!cwd) { return; }
    const name = await vscode.window.showInputBox({
      prompt: "Name of quarantined file to restore",
    });
    if (!name) { return; }
    await runVelka(["quarantine", "restore", name], cwd, channel);
  });

  // ── Feedback ──────────────────────────────────────────────────────────────

  reg("velka.feedbackMark", async () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor) { return; }
    const cwd = getWorkspaceRoot();
    if (!cwd) { return; }
    const file = editor.document.uri.fsPath;
    const line = String(editor.selection.active.line + 1);
    await runVelka(
      ["feedback", "mark", "--file", file, "--line", line],
      cwd,
      channel
    );
  });

  reg("velka.feedbackList", async () => {
    const cwd = getWorkspaceRoot();
    if (!cwd) { return; }
    await runVelka(["feedback", "list"], cwd, channel);
  });

  reg("velka.feedbackClear", async () => {
    const ok = await vscode.window.showWarningMessage(
      "Clear all false positive entries?",
      "Clear",
      "Cancel"
    );
    if (ok !== "Clear") { return; }
    const cwd = getWorkspaceRoot();
    if (!cwd) { return; }
    await runVelka(["feedback", "clear"], cwd, channel);
  });

  // ── Interactive terminals ─────────────────────────────────────────────────

  reg("velka.openTui", async () => {
    const cwd = getWorkspaceRoot();
    if (!cwd) { return; }
    const t = vscode.window.createTerminal({ name: "Velka TUI", cwd });
    t.show();
    t.sendText(`"${_bin}" tui .`);
  });

  reg("velka.runtime", async () => {
    const cwd = getWorkspaceRoot();
    if (!cwd) { return; }
    const logPath = await vscode.window.showInputBox({
      prompt:
        "Log file path(s) to monitor (space-separated). Leave empty to read stdin.",
      placeHolder: "/var/log/app.log",
    });
    const args = ["runtime"];
    if (logPath?.trim()) {
      args.push(...logPath.trim().split(/\s+/), "--follow");
    }
    const t = vscode.window.createTerminal({
      name: "Velka Runtime Monitor",
      cwd,
    });
    t.show();
    t.sendText(`"${_bin}" ${args.join(" ")}`);
  });

  // ── Tree view ─────────────────────────────────────────────────────────────

  reg("velka.refreshFindings", async () => {
    _provider.refresh();
  });
}
