import * as vscode from "vscode";

interface GroupNode {
  kind: "group";
  label: string;
  severity: vscode.DiagnosticSeverity;
  children: FileNode[];
}

interface FileNode {
  kind: "file";
  uri: vscode.Uri;
  children: FindingNode[];
}

interface FindingNode {
  kind: "finding";
  diagnostic: vscode.Diagnostic;
  uri: vscode.Uri;
}

type TreeNode = GroupNode | FileNode | FindingNode;

const SEVERITY_LABELS: Record<number, string> = {
  [vscode.DiagnosticSeverity.Error]:       "\uD83D\uDD34 Critical",
  [vscode.DiagnosticSeverity.Warning]:     "\uD83D\uDFE0 High / Medium",
  [vscode.DiagnosticSeverity.Information]: "\uD83D\uDD35 Low",
  [vscode.DiagnosticSeverity.Hint]:        "\u26AA Informational",
};

const SEVERITY_ORDER = [
  vscode.DiagnosticSeverity.Error,
  vscode.DiagnosticSeverity.Warning,
  vscode.DiagnosticSeverity.Information,
  vscode.DiagnosticSeverity.Hint,
];

export class FindingsProvider implements vscode.TreeDataProvider<TreeNode> {
  private readonly _onDidChangeTreeData =
    new vscode.EventEmitter<TreeNode | undefined | null | void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  constructor(context: vscode.ExtensionContext) {
    context.subscriptions.push(
      vscode.languages.onDidChangeDiagnostics(() =>
        this._onDidChangeTreeData.fire()
      )
    );
  }

  refresh(): void {
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(node: TreeNode): vscode.TreeItem {
    if (node.kind === "group") {
      const count = node.children.reduce((s, f) => s + f.children.length, 0);
      const item = new vscode.TreeItem(
        `${node.label} (${count})`,
        count > 0
          ? vscode.TreeItemCollapsibleState.Expanded
          : vscode.TreeItemCollapsibleState.None
      );
      item.contextValue = "velka-group";
      return item;
    }

    if (node.kind === "file") {
      const label = vscode.workspace.asRelativePath(node.uri);
      const item = new vscode.TreeItem(
        label,
        vscode.TreeItemCollapsibleState.Expanded
      );
      item.resourceUri = node.uri;
      item.iconPath = vscode.ThemeIcon.File;
      item.contextValue = "velka-file";
      return item;
    }

    // finding
    const d = node.diagnostic;
    const line = d.range.start.line + 1;
    const summary = d.message.split("\n")[0];
    const item = new vscode.TreeItem(
      `Line ${line}: ${summary}`,
      vscode.TreeItemCollapsibleState.None
    );
    item.command = {
      command: "vscode.open",
      title: "Open finding",
      arguments: [node.uri, { selection: d.range }],
    };
    item.tooltip = d.message;
    item.iconPath =
      d.severity === vscode.DiagnosticSeverity.Error
        ? new vscode.ThemeIcon(
            "error",
            new vscode.ThemeColor("problemsErrorIcon.foreground")
          )
        : new vscode.ThemeIcon(
            "warning",
            new vscode.ThemeColor("problemsWarningIcon.foreground")
          );
    item.contextValue = "velka-finding";
    return item;
  }

  getChildren(node?: TreeNode): TreeNode[] {
    if (!node)             { return this.buildGroups(); }
    if (node.kind === "group") { return node.children; }
    if (node.kind === "file")  { return node.children; }
    return [];
  }

  private buildGroups(): GroupNode[] {
    const byGroup = new Map<
      vscode.DiagnosticSeverity,
      Map<string, FindingNode[]>
    >();

    for (const [uri, diags] of vscode.languages.getDiagnostics()) {
      for (const d of diags) {
        if (d.source !== "velka") { continue; }
        const sev = d.severity ?? vscode.DiagnosticSeverity.Warning;
        if (!byGroup.has(sev)) { byGroup.set(sev, new Map()); }
        const byFile = byGroup.get(sev)!;
        const key = uri.toString();
        if (!byFile.has(key)) { byFile.set(key, []); }
        byFile.get(key)!.push({ kind: "finding", diagnostic: d, uri });
      }
    }

    const groups: GroupNode[] = [];
    for (const sev of SEVERITY_ORDER) {
      const byFile = byGroup.get(sev);
      if (!byFile || byFile.size === 0) { continue; }
      const fileNodes: FileNode[] = [];
      for (const [uriStr, findings] of byFile) {
        fileNodes.push({
          kind: "file",
          uri: vscode.Uri.parse(uriStr),
          children: findings,
        });
      }
      groups.push({
        kind: "group",
        label: SEVERITY_LABELS[sev] ?? `Severity ${sev}`,
        severity: sev,
        children: fileNodes,
      });
    }
    return groups;
  }
}
