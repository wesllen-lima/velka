import * as vscode from "vscode";
import { exec } from "child_process";
import { promisify } from "util";

const execAsync = promisify(exec);

const OUTPUT_CHANNEL_NAME = "Velka";

export function activate(context: vscode.ExtensionContext): void {
  const disposable = vscode.commands.registerCommand(
    "velka.scan",
    async () => {
      const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
      if (!workspaceFolder) {
        vscode.window.showErrorMessage("No workspace folder open.");
        return;
      }

      const channel = vscode.window.createOutputChannel(OUTPUT_CHANNEL_NAME);
      channel.clear();
      channel.show();
      channel.appendLine("Running Velka scan...");

      try {
        const { stdout, stderr } = await execAsync("velka scan . --format terminal", {
          cwd: workspaceFolder.uri.fsPath,
          maxBuffer: 10 * 1024 * 1024,
        });
        if (stdout) {
          channel.append(stdout);
        }
        if (stderr) {
          channel.append(stderr);
        }
        channel.appendLine("\nScan complete.");
      } catch (err: unknown) {
        const e = err as { stdout?: string; stderr?: string; code?: number };
        if (e.stdout) {
          channel.append(e.stdout);
        }
        if (e.stderr) {
          channel.append(e.stderr);
        }
        if (e.code === 1) {
          channel.appendLine("\nVelka found secrets (exit code 1).");
        } else {
          channel.appendLine(`\nError: ${e}`);
          vscode.window.showErrorMessage(
            "Velka scan failed. Ensure 'velka' is on PATH (cargo install velka)."
          );
        }
      }
    }
  );

  context.subscriptions.push(disposable);
}

export function deactivate(): void {}
