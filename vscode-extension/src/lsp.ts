import * as vscode from "vscode";
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
} from "vscode-languageclient/node";

let client: LanguageClient | undefined;

export async function startLspClient(
  binaryPath: string,
  context: vscode.ExtensionContext
): Promise<LanguageClient> {
  const serverOptions: ServerOptions = {
    command: binaryPath,
    args: ["lsp"],
  };

  const clientOptions: LanguageClientOptions = {
    // Activate for all file types — velka scans any language
    documentSelector: [{ scheme: "file" }],
    synchronize: {
      fileEvents: vscode.workspace.createFileSystemWatcher("**/*"),
    },
    outputChannelName: "Velka LSP",
  };

  client = new LanguageClient(
    "velka-lsp",
    "Velka LSP",
    serverOptions,
    clientOptions
  );

  // Client implements Disposable — will be stopped on extension deactivate
  context.subscriptions.push(client);
  await client.start();
  return client;
}

export function getClient(): LanguageClient | undefined {
  return client;
}

export async function stopLspClient(): Promise<void> {
  if (client) {
    await client.stop();
    client = undefined;
  }
}
