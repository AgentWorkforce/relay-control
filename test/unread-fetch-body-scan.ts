// Static scan for fetch responses whose body is never read or released.
//
// An unread response body keeps the upstream request open, and in Node (undici) it can hold the
// socket until the response is garbage collected. The scan parses each file with the TypeScript
// compiler, so comments and string contents (including the inline browser scripts some pages
// embed) can never satisfy or trip it.
//
// A fetch-like call is a call whose callee is `fetch`, `fetchImpl`, `fetcher`, `fetchFn`, or any
// name ending in `Fetch` (`timedFetch`, `agentDmFetch`), either bare or as a property
// (`globalThis.fetch`, `this.fetchImpl`, `env.SERVICE.fetch`).
//
// For `const X = await fetchLike(...)` and `X = await fetchLike(...)` the scan requires at least
// one later use of X that consumes or hands off the body: `X.text|json|arrayBuffer|blob|formData|
// bytes()`, any use of `X.body` (including `X.body?.cancel()`), passing X to a function (including
// `drainBody(X, ...)`), returning X, or aliasing X into another binding, object or array. A use that
// sits only inside the `then` branch of `if (!X.ok) { ... }` does not count, because the success
// path still leaks. An `await fetchLike(...)` or `void fetchLike(...)` statement whose result is
// discarded is always a finding.
import ts from "typescript";

export type UnreadBodyFinding = {
  file: string;
  line: number;
  binding: string;
  kind: "unread" | "discarded";
  text: string;
};

const FETCH_NAME = /^(?:fetch|fetchImpl|fetcher|fetchFn)$|[a-z]Fetch$/;
const CONSUMING_METHODS = new Set(["text", "json", "arrayBuffer", "blob", "formData", "bytes"]);

function calleeName(expression: ts.Expression): string | undefined {
  if (ts.isIdentifier(expression)) return expression.text;
  if (ts.isPropertyAccessExpression(expression)) return expression.name.text;
  return undefined;
}

function isFetchCall(node: ts.Node): node is ts.CallExpression {
  if (!ts.isCallExpression(node)) return false;
  const name = calleeName(node.expression);
  return name !== undefined && FETCH_NAME.test(name);
}

function skipWrappers(node: ts.Node): ts.Node {
  let current = node.parent;
  while (
    ts.isParenthesizedExpression(current) ||
    ts.isAsExpression(current) ||
    ts.isNonNullExpression(current) ||
    ts.isSatisfiesExpression(current) ||
    ts.isTypeAssertionExpression(current)
  ) {
    current = current.parent;
  }
  return current;
}

function unwrap(expression: ts.Expression): ts.Expression {
  let current = expression;
  while (ts.isParenthesizedExpression(current) || ts.isNonNullExpression(current) || ts.isAsExpression(current)) {
    current = current.expression;
  }
  return current;
}

function enclosingScope(node: ts.Node): ts.Node {
  let current: ts.Node = node.parent;
  while (current && !ts.isFunctionLike(current) && !ts.isSourceFile(current)) current = current.parent;
  return current ?? node.getSourceFile();
}

// `if (!X.ok) { ... }`: true when `reference` sits inside the then-branch of such a guard.
function onlyOnFailurePath(reference: ts.Identifier, name: string, scope: ts.Node): boolean {
  let current: ts.Node = reference;
  while (current.parent && current !== scope) {
    const parent: ts.Node = current.parent;
    if (ts.isIfStatement(parent) && parent.thenStatement === current) {
      const condition = unwrap(parent.expression);
      if (
        ts.isPrefixUnaryExpression(condition) &&
        condition.operator === ts.SyntaxKind.ExclamationToken
      ) {
        const operand = unwrap(condition.operand);
        if (
          ts.isPropertyAccessExpression(operand) &&
          operand.name.text === "ok" &&
          ts.isIdentifier(unwrap(operand.expression)) &&
          (unwrap(operand.expression) as ts.Identifier).text === name
        ) {
          return true;
        }
      }
    }
    current = parent;
  }
  return false;
}

function consumes(reference: ts.Identifier): boolean {
  let node: ts.Node = reference;
  while (ts.isParenthesizedExpression(node.parent) || ts.isNonNullExpression(node.parent) || ts.isAsExpression(node.parent)) {
    node = node.parent;
  }
  const parent = node.parent;
  if (ts.isPropertyAccessExpression(parent) && parent.expression === node) {
    const member = parent.name.text;
    if (member === "body") return true;
    if (CONSUMING_METHODS.has(member)) return ts.isCallExpression(parent.parent) && parent.parent.expression === parent;
    return false;
  }
  if (ts.isCallExpression(parent) || ts.isNewExpression(parent)) return parent.arguments?.includes(node as ts.Expression) ?? false;
  if (ts.isReturnStatement(parent)) return true;
  if (ts.isArrowFunction(parent) && parent.body === node) return true;
  if (ts.isShorthandPropertyAssignment(parent)) return true;
  if (ts.isPropertyAssignment(parent) && parent.initializer === node) return true;
  if (ts.isArrayLiteralExpression(parent) || ts.isSpreadElement(parent)) return true;
  if (ts.isVariableDeclaration(parent) && parent.initializer === node) return true;
  if (
    ts.isBinaryExpression(parent) &&
    parent.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
    parent.right === node
  ) {
    return true;
  }
  return false;
}

function references(scope: ts.Node, name: string, after: number): ts.Identifier[] {
  const found: ts.Identifier[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isIdentifier(node) && node.text === name && node.getStart() >= after) {
      const parent = node.parent;
      // `other.X` and `{ X: value }` keys are not references to the binding.
      const isMemberName = ts.isPropertyAccessExpression(parent) && parent.name === node;
      const isKey = ts.isPropertyAssignment(parent) && parent.name === node;
      if (!isMemberName && !isKey) found.push(node);
    }
    ts.forEachChild(node, visit);
  };
  visit(scope);
  return found;
}

export function scanSourceForUnreadBodies(file: string, source: string): UnreadBodyFinding[] {
  const sourceFile = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const findings: UnreadBodyFinding[] = [];
  const report = (node: ts.Node, binding: string, kind: UnreadBodyFinding["kind"]): void => {
    const { line } = sourceFile.getLineAndCharacterOfPosition(node.getStart());
    findings.push({ file, line: line + 1, binding, kind, text: node.getText().split("\n")[0]!.slice(0, 120) });
  };

  const visit = (node: ts.Node): void => {
    if ((ts.isAwaitExpression(node) || ts.isVoidExpression(node)) && isFetchCall(unwrap(node.expression))) {
      const parent = skipWrappers(node);
      if (ts.isExpressionStatement(parent)) {
        report(node, "<discarded>", "discarded");
      } else if (ts.isAwaitExpression(node)) {
        let binding: string | undefined;
        if (ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) binding = parent.name.text;
        else if (
          ts.isBinaryExpression(parent) &&
          parent.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
          ts.isIdentifier(unwrap(parent.left))
        ) {
          binding = (unwrap(parent.left) as ts.Identifier).text;
        }
        if (binding !== undefined) {
          const scope = enclosingScope(node);
          const used = references(scope, binding, node.getEnd()).some(
            (reference) => consumes(reference) && !onlyOnFailurePath(reference, binding, scope),
          );
          if (!used) report(node, binding, "unread");
        } else if (ts.isPropertyAccessExpression(parent)) {
          // `(await fetch(url)).ok` reads only metadata and drops the body.
          const member = parent.name.text;
          const read = member === "body" || (CONSUMING_METHODS.has(member) && ts.isCallExpression(parent.parent));
          if (!read) report(node, `<.${member}>`, "unread");
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return findings;
}
