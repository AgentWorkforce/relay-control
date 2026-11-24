// Static scan for fetch responses whose body is never read or released.
//
// An unread response body keeps the upstream request open, and in Node (undici) it can hold the
// socket until the response is garbage collected. The scan parses each file with the TypeScript
// compiler, so comments and string contents (including the inline browser scripts some pages
// embed) can never satisfy or trip it. It is syntactic and works one file at a time: it does not
// use the type checker.
//
// A fetch-like call is a call whose callee is one of:
// - `fetch`, `fetchImpl`, `fetcher`, `fetchFn`, or any name ending in `Fetch` (`timedFetch`), bare
//   or as a property (`globalThis.fetch`, `this.fetchImpl`, `env.SERVICE.fetch`);
// - a name declared in the same file with a fetch type (`typeof fetch`, or a same-file alias of a
//   function type returning `Promise<Response>`), such as `http: typeof fetch` in a deps type;
// - a same-file function or method declared to return `Promise<Response>` (`this.request(...)`);
// - a call to a same-file function declared to return a fetch type (`call(deps)(...)`);
// - a parenthesised `a ?? b`, `a || b` or `c ? a : b` where either side is fetch-like
//   (`(options.fetchImpl ?? fetch)(...)`).
// A same-file function declared to return an object type with a `Response`-typed property
// (`Promise<{ status: number; response: Response }>`) is a carrier: destructuring that property
// is tracked as a binding, and dropping it is a finding.
//
// The result of the call is followed through parentheses, `await`, `.catch(...)`/`.finally(...)`,
// the branches of `?:`, and an element of `Promise.all([...])`. Then:
// - a discarded result (`await fetch(u);`, `fetch(u).catch(...);`, `void fetch(u)`) is a finding;
// - `(await fetch(u)).ok` reads metadata only and is a finding;
// - `const { ok } = await fetch(u)` is a finding unless it destructures `body`;
// - `.then(cb)` checks the callback's first parameter as a binding;
// - `const X = await ...`, `X = await ...`, and destructured or `Promise.all` bindings are checked.
//
// A binding is consumed when a later use, in the binding's own scope and not shadowed by a nested
// declaration of the same name, reads or hands off the body: `X.text|json|arrayBuffer|blob|
// formData|bytes()`; `X.body` used as a stream (`.cancel()`, `.getReader()`, `.pipeTo()`, `.tee()`,
// `for await ... of`, passed or returned; a test such as `if (X.body)` does not count); passing X
// to `drainBody` or to a function outside this file; passing X to a same-file function whose
// parameter is itself consumed; returning X; or aliasing X into an object, array or another
// binding that is consumed. Passing X (or `{ X }`) to a logger (`console.*`, `log`, `*.warn`, ...)
// does not count.
//
// Uses that sit on a branch of an `if` or `?:` whose condition tests `X.ok` or `X.status` (or an
// alias such as a destructured `status`, `const status = X.status` or `status = X.status`) count only when the other
// branch also consumes X, or the other branch only throws (for an `if` without `else`, the
// statements after it). A branch of such an `if` that returns or continues without consuming X is
// a `branch-exit` finding (the `404 -> null` shape), unless X was already consumed before the `if`.
import ts from "typescript";

export type UnreadBodyFinding = {
  file: string;
  line: number;
  binding: string;
  kind: "unread" | "discarded" | "branch-exit";
  text: string;
};

const FETCH_NAME = /^(?:fetch|fetchImpl|fetcher|fetchFn)$|[a-z]Fetch$/;
const CONSUMING_METHODS = new Set(["text", "json", "arrayBuffer", "blob", "formData", "bytes"]);
const BODY_STREAM_METHODS = new Set(["cancel", "getReader", "pipeTo", "pipeThrough", "tee"]);
const LOGGER_METHODS = new Set(["log", "warn", "error", "info", "debug", "trace"]);
const LOGGER_NAMES = new Set(["log", "logger", "console"]);
const RESPONSE_TYPES = new Set(["Response", "globalThis.Response"]);

type CallKind = { kind: "response" } | { kind: "carrier"; properties: string[] };
type FunctionDecl = ts.SignatureDeclaration & { body?: ts.Node };

type Context = {
  fetchTyped: Set<string>;
  responseFns: Set<string>;
  carrierFns: Map<string, string[]>;
  fetchFactories: Set<string>;
  functions: Map<string, FunctionDecl[]>;
  paramMemo: Map<string, boolean>;
};

const compact = (node: ts.Node): string => node.getText().replace(/\s+/g, "");

function promiseInner(type: ts.TypeNode): ts.TypeNode {
  if (
    ts.isTypeReferenceNode(type) &&
    ts.isIdentifier(type.typeName) &&
    type.typeName.text === "Promise" &&
    type.typeArguments?.length === 1
  ) {
    return type.typeArguments[0]!;
  }
  return type;
}

function isResponseType(type: ts.TypeNode | undefined): boolean {
  return type !== undefined && RESPONSE_TYPES.has(compact(promiseInner(type)));
}

function carrierProperties(type: ts.TypeNode | undefined): string[] {
  if (!type) return [];
  const inner = promiseInner(type);
  if (!ts.isTypeLiteralNode(inner)) return [];
  return inner.members
    .filter((member): member is ts.PropertySignature => ts.isPropertySignature(member))
    .filter((member) => ts.isIdentifier(member.name) && isResponseType(member.type))
    .map((member) => (member.name as ts.Identifier).text);
}

function buildContext(sourceFile: ts.SourceFile): Context {
  const fetchAliases = new Set<string>();
  const collectAliases = (node: ts.Node): void => {
    if (ts.isTypeAliasDeclaration(node)) {
      const type = node.type;
      if ((ts.isFunctionTypeNode(type) && isResponseType(type.type)) || /^typeof(?:globalThis\.)?fetch$/.test(compact(type))) {
        fetchAliases.add(node.name.text);
      }
    }
    ts.forEachChild(node, collectAliases);
  };
  collectAliases(sourceFile);
  const isFetchType = (type: ts.TypeNode | undefined): boolean => {
    if (!type) return false;
    const text = compact(type);
    if (/^typeof(?:globalThis\.)?fetch$/.test(text) || fetchAliases.has(text)) return true;
    return ts.isFunctionTypeNode(type) && isResponseType(type.type);
  };

  const context: Context = {
    fetchTyped: new Set(),
    responseFns: new Set(),
    carrierFns: new Map(),
    fetchFactories: new Set(),
    functions: new Map(),
    paramMemo: new Map(),
  };
  const addFunction = (name: string, decl: FunctionDecl): void => {
    const list = context.functions.get(name) ?? [];
    list.push(decl);
    context.functions.set(name, list);
    if (isResponseType(decl.type)) context.responseFns.add(name);
    const carried = carrierProperties(decl.type);
    if (carried.length > 0) context.carrierFns.set(name, carried);
    if (isFetchType(decl.type)) context.fetchFactories.add(name);
  };
  const visit = (node: ts.Node): void => {
    if ((ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node)) && node.name && ts.isIdentifier(node.name)) {
      addFunction(node.name.text, node);
    } else if (
      (ts.isVariableDeclaration(node) || ts.isPropertyDeclaration(node)) &&
      ts.isIdentifier(node.name) &&
      node.initializer &&
      (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer))
    ) {
      addFunction(node.name.text, node.initializer);
    }
    if (
      (ts.isParameter(node) || ts.isPropertyDeclaration(node) || ts.isPropertySignature(node) || ts.isVariableDeclaration(node)) &&
      ts.isIdentifier(node.name) &&
      isFetchType(node.type)
    ) {
      context.fetchTyped.add(node.name.text);
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return context;
}

function calleeName(expression: ts.Expression): string | undefined {
  const callee = unwrap(expression);
  if (ts.isIdentifier(callee)) return callee.text;
  if (ts.isPropertyAccessExpression(callee)) return callee.name.text;
  return undefined;
}

function calleeKind(context: Context, expression: ts.Expression): CallKind | undefined {
  const callee = unwrap(expression);
  if (ts.isIdentifier(callee) || ts.isPropertyAccessExpression(callee)) {
    const name = ts.isIdentifier(callee) ? callee.text : callee.name.text;
    if (FETCH_NAME.test(name) || context.fetchTyped.has(name) || context.responseFns.has(name)) return { kind: "response" };
    const carried = context.carrierFns.get(name);
    if (carried) return { kind: "carrier", properties: carried };
    return undefined;
  }
  if (
    ts.isBinaryExpression(callee) &&
    (callee.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken || callee.operatorToken.kind === ts.SyntaxKind.BarBarToken)
  ) {
    return calleeKind(context, callee.left)?.kind === "response" || calleeKind(context, callee.right)?.kind === "response"
      ? { kind: "response" }
      : undefined;
  }
  if (ts.isConditionalExpression(callee)) {
    return calleeKind(context, callee.whenTrue)?.kind === "response" || calleeKind(context, callee.whenFalse)?.kind === "response"
      ? { kind: "response" }
      : undefined;
  }
  if (ts.isCallExpression(callee)) {
    const factory = calleeName(callee.expression);
    if (factory !== undefined && context.fetchFactories.has(factory)) return { kind: "response" };
  }
  return undefined;
}

function unwrap(expression: ts.Expression): ts.Expression {
  let current = expression;
  while (
    ts.isParenthesizedExpression(current) ||
    ts.isNonNullExpression(current) ||
    ts.isAsExpression(current) ||
    ts.isSatisfiesExpression(current) ||
    ts.isTypeAssertionExpression(current)
  ) {
    current = current.expression;
  }
  return current;
}

function isWrapper(node: ts.Node): node is ts.Expression & { expression: ts.Expression } {
  return (
    ts.isParenthesizedExpression(node) ||
    ts.isAsExpression(node) ||
    ts.isNonNullExpression(node) ||
    ts.isSatisfiesExpression(node) ||
    ts.isTypeAssertionExpression(node)
  );
}

function outerWrapped(node: ts.Node): ts.Node {
  let current = node;
  while (isWrapper(current.parent)) current = current.parent;
  return current;
}

const contains = (outer: ts.Node, inner: ts.Node): boolean => inner.pos >= outer.pos && inner.end <= outer.end;

function bindingNames(name: ts.BindingName, into: string[] = []): string[] {
  if (ts.isIdentifier(name)) into.push(name.text);
  else for (const element of name.elements) if (!ts.isOmittedExpression(element)) bindingNames(element.name, into);
  return into;
}

function declaresName(node: ts.Node, name: string): boolean {
  if (ts.isFunctionLike(node)) return node.parameters.some((parameter) => bindingNames(parameter.name).includes(name));
  if (ts.isCatchClause(node)) return node.variableDeclaration ? bindingNames(node.variableDeclaration.name).includes(name) : false;
  if (ts.isForStatement(node) || ts.isForOfStatement(node) || ts.isForInStatement(node)) {
    const initializer = node.initializer;
    return initializer !== undefined && ts.isVariableDeclarationList(initializer)
      ? initializer.declarations.some((declaration) => bindingNames(declaration.name).includes(name))
      : false;
  }
  if (ts.isBlock(node) || ts.isSourceFile(node) || ts.isModuleBlock(node) || ts.isCaseClause(node) || ts.isDefaultClause(node)) {
    return node.statements.some(
      (statement) =>
        (ts.isVariableStatement(statement) &&
          statement.declarationList.declarations.some((declaration) => bindingNames(declaration.name).includes(name))) ||
        ((ts.isFunctionDeclaration(statement) || ts.isClassDeclaration(statement)) && statement.name?.text === name),
    );
  }
  return false;
}

// Identifiers that refer to the binding `name` declared at `declaration`, after `after`.
function references(scope: ts.Node, name: string, after: number, declaration: ts.Node): ts.Identifier[] {
  const found: ts.Identifier[] = [];
  const visit = (node: ts.Node): void => {
    // A nested declaration of the same name shadows the binding for its whole subtree.
    if (node !== scope && !contains(node, declaration) && declaresName(node, name)) return;
    if (ts.isIdentifier(node) && node.text === name && node.getStart() >= after) {
      const parent = node.parent;
      const isMemberName = ts.isPropertyAccessExpression(parent) && parent.name === node;
      const isKey = ts.isBindingElement(parent) && parent.propertyName === node;
      const isPropertyKey = ts.isPropertyAssignment(parent) && parent.name === node;
      const isDeclarationName =
        (ts.isVariableDeclaration(parent) || ts.isParameter(parent) || ts.isBindingElement(parent)) && parent.name === node;
      if (!isMemberName && !isKey && !isPropertyKey && !isDeclarationName) found.push(node);
    }
    ts.forEachChild(node, visit);
  };
  visit(scope);
  return found;
}

function enclosingFunction(node: ts.Node): ts.Node {
  let current: ts.Node = node.parent;
  while (current && !ts.isFunctionLike(current) && !ts.isSourceFile(current)) current = current.parent;
  return current ?? node.getSourceFile();
}

function declarationScope(declaration: ts.VariableDeclaration): ts.Node {
  const list = declaration.parent;
  if (!ts.isVariableDeclarationList(list)) return enclosingFunction(declaration);
  if (!(ts.getCombinedNodeFlags(declaration) & ts.NodeFlags.BlockScoped)) return enclosingFunction(declaration);
  return ts.isVariableStatement(list.parent) ? list.parent.parent : list.parent;
}

function isLoggerCallee(expression: ts.Expression): boolean {
  const callee = unwrap(expression);
  if (ts.isIdentifier(callee)) return LOGGER_NAMES.has(callee.text);
  if (ts.isPropertyAccessExpression(callee)) {
    const target = unwrap(callee.expression);
    if (ts.isIdentifier(target) && target.text === "console") return true;
    return LOGGER_METHODS.has(callee.name.text) || LOGGER_NAMES.has(callee.name.text);
  }
  return false;
}

// True when `node` (an object/array literal member) ends up as an argument of a logger call.
function insideLoggerArgument(node: ts.Node): boolean {
  let current: ts.Node = node;
  while (
    ts.isObjectLiteralExpression(current.parent) ||
    ts.isArrayLiteralExpression(current.parent) ||
    ts.isPropertyAssignment(current.parent) ||
    ts.isShorthandPropertyAssignment(current.parent) ||
    ts.isSpreadElement(current.parent) ||
    ts.isSpreadAssignment(current.parent) ||
    isWrapper(current.parent)
  ) {
    current = current.parent;
  }
  const parent = current.parent;
  return ts.isCallExpression(parent) && parent.arguments.includes(current as ts.Expression) && isLoggerCallee(parent.expression);
}

// Exits that leave a branch normally (not by throwing), ignoring nested functions.
function hasNormalExit(node: ts.Node): boolean {
  let found = false;
  const visit = (child: ts.Node): void => {
    if (found || (child !== node && ts.isFunctionLike(child))) return;
    if (ts.isReturnStatement(child) || ts.isContinueStatement(child)) found = true;
    else ts.forEachChild(child, visit);
  };
  visit(node);
  return found;
}

function hasThrow(node: ts.Node): boolean {
  let found = false;
  const visit = (child: ts.Node): void => {
    if (found || (child !== node && ts.isFunctionLike(child))) return;
    if (ts.isThrowStatement(child)) found = true;
    else ts.forEachChild(child, visit);
  };
  visit(node);
  return found;
}

const failureOnly = (node: ts.Node): boolean => hasThrow(node) && !hasNormalExit(node) && !hasBreak(node);

function hasBreak(node: ts.Node): boolean {
  let found = false;
  const visit = (child: ts.Node): void => {
    if (found || (child !== node && ts.isFunctionLike(child))) return;
    if (ts.isBreakStatement(child)) found = true;
    else ts.forEachChild(child, visit);
  };
  visit(node);
  return found;
}

// For an `if` without `else`: do the statements after it end in a throw before any normal exit?
function continuationThrows(statement: ts.IfStatement): boolean {
  const parent = statement.parent;
  if (!(ts.isBlock(parent) || ts.isSourceFile(parent) || ts.isCaseClause(parent) || ts.isDefaultClause(parent))) return false;
  const rest = parent.statements.slice(parent.statements.indexOf(statement) + 1);
  for (const next of rest) {
    if (hasNormalExit(next) || hasBreak(next)) return false;
    if (ts.isThrowStatement(next)) return true;
  }
  return false;
}

type Binding = { name: string; scope: ts.Node; after: number; declaration: ts.Node; aliases: string[] };
type BindingResult = { consumed: boolean; exits: ts.Node[] };

function analyseBinding(context: Context, binding: Binding): BindingResult {
  const refs = references(binding.scope, binding.name, binding.after, binding.declaration);
  const aliases = new Set(binding.aliases);
  // `const status = X.status` / `const ok = X.ok` make `status` / `ok` stand for the binding in tests.
  for (const ref of refs) {
    const access = outerWrapped(ref).parent;
    if (ts.isPropertyAccessExpression(access) && (access.name.text === "ok" || access.name.text === "status")) {
      const holder = outerWrapped(access).parent;
      if (ts.isVariableDeclaration(holder) && ts.isIdentifier(holder.name)) aliases.add(holder.name.text);
      else if (
        ts.isBinaryExpression(holder) &&
        holder.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        ts.isIdentifier(unwrap(holder.left))
      ) {
        aliases.add((unwrap(holder.left) as ts.Identifier).text);
      }
    }
  }
  const testsStatus = (condition: ts.Node): boolean => {
    let found = false;
    const visit = (node: ts.Node): void => {
      if (found) return;
      if (ts.isPropertyAccessExpression(node) && (node.name.text === "ok" || node.name.text === "status")) {
        const target = unwrap(node.expression);
        if (ts.isIdentifier(target) && target.text === binding.name) found = true;
      } else if (ts.isIdentifier(node) && aliases.has(node.text)) {
        const parent = node.parent;
        if (!(ts.isPropertyAccessExpression(parent) && parent.name === node)) found = true;
      }
      ts.forEachChild(node, visit);
    };
    visit(condition);
    return found;
  };

  const consuming = refs.filter((ref) => consumes(context, ref));
  const consumedWithin = (node: ts.Node | undefined): boolean => node !== undefined && consuming.some((ref) => contains(node, ref));

  type Branch = { conditional: ts.IfStatement | ts.ConditionalExpression; side: "then" | "else" };
  const statusBranches = (ref: ts.Node): Branch[] => {
    const branches: Branch[] = [];
    let current: ts.Node = ref;
    while (current.parent && current !== binding.scope) {
      const parent: ts.Node = current.parent;
      if (ts.isIfStatement(parent) && current !== parent.expression && testsStatus(parent.expression)) {
        branches.push({ conditional: parent, side: parent.thenStatement === current ? "then" : "else" });
      } else if (ts.isConditionalExpression(parent) && current !== parent.condition && testsStatus(parent.condition)) {
        branches.push({ conditional: parent, side: parent.whenTrue === current ? "then" : "else" });
      }
      current = parent;
    }
    return branches;
  };
  const otherSideCovered = ({ conditional, side }: Branch): boolean => {
    if (ts.isConditionalExpression(conditional)) {
      return consumedWithin(side === "then" ? conditional.whenFalse : conditional.whenTrue);
    }
    const other = side === "then" ? conditional.elseStatement : conditional.thenStatement;
    if (other === undefined) return continuationThrows(conditional);
    return consumedWithin(other) || failureOnly(other);
  };
  const counts = (ref: ts.Node): boolean => statusBranches(ref).every(otherSideCovered);
  const unconditional = consuming.filter((ref) => statusBranches(ref).length === 0);
  const consumed = consuming.some(counts);

  // Branches of a status-testing `if` that leave normally without releasing the body.
  const exits: ts.Node[] = [];
  if (consumed) {
    const seen = new Set<ts.IfStatement>();
    const testRefs = [
      ...refs,
      ...[...aliases].flatMap((alias) => references(binding.scope, alias, binding.after, binding.declaration)),
    ];
    for (const ref of testRefs) {
      let current: ts.Node = ref;
      while (current.parent && current !== binding.scope && !ts.isStatement(current)) {
        const parent: ts.Node = current.parent;
        if (ts.isIfStatement(parent) && parent.expression === current) {
          if (!seen.has(parent) && testsStatus(parent.expression)) seen.add(parent);
          break;
        }
        current = parent;
      }
    }
    for (const statement of seen) {
      if (unconditional.some((ref) => ref.end <= statement.getStart())) continue;
      for (const side of [statement.thenStatement, statement.elseStatement]) {
        if (side && hasNormalExit(side) && !consumedWithin(side)) exits.push(side);
      }
    }
  }
  return { consumed, exits };
}

// A use of `X.body` that reads or releases the stream (not a test such as `if (X.body)`).
function bodyUseConsumes(access: ts.PropertyAccessExpression): boolean {
  const node = outerWrapped(access);
  const parent = node.parent;
  if (ts.isPropertyAccessExpression(parent) && parent.expression === node) {
    return BODY_STREAM_METHODS.has(parent.name.text) && ts.isCallExpression(parent.parent) && parent.parent.expression === parent;
  }
  if (ts.isCallExpression(parent) && parent.arguments.includes(node as ts.Expression)) return !isLoggerCallee(parent.expression);
  if (ts.isNewExpression(parent)) return true;
  if (ts.isForOfStatement(parent) && parent.expression === node) return true;
  if (ts.isReturnStatement(parent) || ts.isYieldExpression(parent)) return true;
  if (ts.isArrowFunction(parent) && parent.body === node) return true;
  if (ts.isVariableDeclaration(parent) && parent.initializer === node) return true;
  if (ts.isBinaryExpression(parent) && parent.operatorToken.kind === ts.SyntaxKind.EqualsToken && parent.right === node) return true;
  if (ts.isPropertyAssignment(parent) || ts.isArrayLiteralExpression(parent) || ts.isSpreadElement(parent)) {
    return !insideLoggerArgument(parent);
  }
  return false;
}

// Is parameter `index` of the same-file function called through `callee` consumed? Undefined when
// the callee is not declared in this file.
function parameterConsumed(context: Context, callee: ts.Expression, index: number): boolean | undefined {
  const name = calleeName(callee);
  const declarations = name === undefined ? undefined : context.functions.get(name);
  if (!declarations) return undefined;
  return declarations.some((declaration) => {
    const parameter = declaration.parameters[index];
    if (!parameter) return false;
    if (parameter.dotDotDotToken || !ts.isIdentifier(parameter.name) || !declaration.body) return true;
    const key = `${declaration.pos}:${index}`;
    const memo = context.paramMemo.get(key);
    if (memo !== undefined) return memo;
    context.paramMemo.set(key, true); // a recursive call is assumed to consume
    const { consumed } = analyseBinding(context, {
      name: parameter.name.text,
      scope: declaration,
      after: parameter.end,
      declaration: parameter,
      aliases: [],
    });
    context.paramMemo.set(key, consumed);
    return consumed;
  });
}

function consumes(context: Context, reference: ts.Identifier): boolean {
  const node = outerWrapped(reference);
  const parent = node.parent;
  if (ts.isPropertyAccessExpression(parent) && parent.expression === node) {
    const member = parent.name.text;
    if (member === "body") return bodyUseConsumes(parent);
    if (CONSUMING_METHODS.has(member)) return ts.isCallExpression(parent.parent) && parent.parent.expression === parent;
    return false;
  }
  if (ts.isCallExpression(parent) && parent.arguments.includes(node as ts.Expression)) {
    if (isLoggerCallee(parent.expression)) return false;
    if (calleeName(parent.expression) === "drainBody") return true;
    return parameterConsumed(context, parent.expression, parent.arguments.indexOf(node as ts.Expression)) ?? true;
  }
  if (ts.isNewExpression(parent)) return true;
  if (ts.isReturnStatement(parent) || ts.isYieldExpression(parent)) return true;
  if (ts.isArrowFunction(parent) && parent.body === node) return true;
  if (
    ts.isShorthandPropertyAssignment(parent) ||
    (ts.isPropertyAssignment(parent) && parent.initializer === node) ||
    ts.isArrayLiteralExpression(parent) ||
    ts.isSpreadElement(parent)
  ) {
    return !insideLoggerArgument(parent);
  }
  if (ts.isVariableDeclaration(parent) && parent.initializer === node) {
    if (ts.isIdentifier(parent.name)) {
      return analyseBinding(context, {
        name: parent.name.text,
        scope: declarationScope(parent),
        after: parent.end,
        declaration: parent,
        aliases: [],
      }).consumed;
    }
    return bindingNames(parent.name).includes("body");
  }
  if (ts.isBinaryExpression(parent) && parent.operatorToken.kind === ts.SyntaxKind.EqualsToken && parent.right === node) return true;
  return false;
}

export function scanSourceForUnreadBodies(file: string, source: string): UnreadBodyFinding[] {
  const sourceFile = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const context = buildContext(sourceFile);
  const findings: UnreadBodyFinding[] = [];
  const report = (node: ts.Node, binding: string, kind: UnreadBodyFinding["kind"]): void => {
    const { line } = sourceFile.getLineAndCharacterOfPosition(node.getStart());
    findings.push({ file, line: line + 1, binding, kind, text: node.getText().split("\n")[0]!.slice(0, 120) });
  };
  const checkBinding = (at: ts.Node, binding: Binding): void => {
    const { consumed, exits } = analyseBinding(context, binding);
    if (!consumed) report(at, binding.name, "unread");
    for (const exit of exits) report(exit, binding.name, "branch-exit");
  };
  const checkVariable = (at: ts.Node, declaration: ts.VariableDeclaration, name: string, nameNode: ts.Node, aliases: string[]): void => {
    checkBinding(at, { name, scope: declarationScope(declaration), after: declaration.end, declaration: nameNode, aliases });
  };
  // `const { a, b: c } = ...`: the local name bound for property `property`, and sibling status aliases.
  const destructured = (pattern: ts.ObjectBindingPattern, property: string): { local?: string; node?: ts.Node; aliases: string[] } => {
    const aliases: string[] = [];
    let local: string | undefined;
    let node: ts.Node | undefined;
    for (const element of pattern.elements) {
      const key = element.propertyName && ts.isIdentifier(element.propertyName) ? element.propertyName.text : ts.isIdentifier(element.name) ? element.name.text : undefined;
      if (!ts.isIdentifier(element.name)) continue;
      if (key === property) {
        local = element.name.text;
        node = element;
      } else if (key === "status" || key === "ok") {
        aliases.push(element.name.text);
      }
    }
    return { local, node, aliases };
  };

  // Follow the call's value through wrappers, `await`, `.catch`/`.finally`, and `?:` branches.
  const follow = (start: ts.Expression): { node: ts.Expression; awaited: boolean } => {
    let current = start;
    let awaited = false;
    for (;;) {
      const parent = current.parent;
      if (isWrapper(parent)) current = parent;
      else if (ts.isAwaitExpression(parent)) {
        awaited = true;
        current = parent;
      } else if (ts.isConditionalExpression(parent) && (parent.whenTrue === current || parent.whenFalse === current)) {
        current = parent;
      } else if (
        ts.isPropertyAccessExpression(parent) &&
        parent.expression === current &&
        (parent.name.text === "catch" || parent.name.text === "finally") &&
        ts.isCallExpression(parent.parent) &&
        parent.parent.expression === parent
      ) {
        current = parent.parent;
      } else {
        return { node: current, awaited };
      }
    }
  };

  const checkCall = (call: ts.CallExpression, kind: CallKind): void => {
    let { node, awaited } = follow(call);
    let parent = node.parent;
    let elementIndex: number | undefined;
    // `Promise.all([fetch(a), ...])`: follow the array result, tracking this element's index.
    if (ts.isArrayLiteralExpression(parent) && ts.isCallExpression(parent.parent)) {
      const all = parent.parent;
      const callee = unwrap(all.expression);
      if (
        all.arguments[0] === parent &&
        ts.isPropertyAccessExpression(callee) &&
        ts.isIdentifier(callee.expression) &&
        callee.expression.text === "Promise" &&
        callee.name.text === "all"
      ) {
        elementIndex = parent.elements.indexOf(node);
        ({ node, awaited } = follow(all));
        parent = node.parent;
        if (ts.isExpressionStatement(parent) || ts.isVoidExpression(parent)) {
          report(call, "<discarded>", "discarded");
          return;
        }
        if (awaited && ts.isVariableDeclaration(parent) && ts.isArrayBindingPattern(parent.name) && kind.kind === "response") {
          const element = parent.name.elements[elementIndex];
          if (!element || ts.isOmittedExpression(element) || element.dotDotDotToken) report(call, `<[${elementIndex}]>`, "unread");
          else if (ts.isIdentifier(element.name)) checkVariable(call, parent, element.name.text, element, []);
          else if (!bindingNames(element.name).includes("body")) report(call, `<[${elementIndex}]>`, "unread");
        }
        return;
      }
    }
    if (ts.isExpressionStatement(parent) || ts.isVoidExpression(parent)) {
      report(call, "<discarded>", "discarded");
      return;
    }
    if (ts.isPropertyAccessExpression(parent) && parent.expression === node) {
      const member = parent.name.text;
      if (!awaited && member === "then" && ts.isCallExpression(parent.parent) && kind.kind === "response") {
        const callback = parent.parent.arguments[0];
        if (callback && (ts.isArrowFunction(callback) || ts.isFunctionExpression(callback))) {
          const parameter = callback.parameters[0];
          if (!parameter) report(call, "<then>", "unread");
          else if (ts.isIdentifier(parameter.name)) {
            checkBinding(call, { name: parameter.name.text, scope: callback, after: parameter.end, declaration: parameter, aliases: [] });
          } else if (!bindingNames(parameter.name).includes("body")) report(call, "<then>", "unread");
        } else if (callback && parameterConsumed(context, callback, 0) === false) {
          report(call, "<then>", "unread");
        }
        return;
      }
      if (awaited && kind.kind === "response") {
        const read = member === "body" ? bodyUseConsumes(parent) : CONSUMING_METHODS.has(member) && ts.isCallExpression(parent.parent);
        if (!read) report(call, `<.${member}>`, "unread");
      }
      return;
    }
    if (!awaited) return; // a promise handed somewhere else: out of scope
    if (ts.isVariableDeclaration(parent) && parent.initializer === node) {
      if (ts.isIdentifier(parent.name)) {
        if (kind.kind === "response") checkVariable(call, parent, parent.name.text, parent, []);
        return; // a carrier object bound whole: handed off
      }
      if (ts.isObjectBindingPattern(parent.name)) {
        if (kind.kind === "response") {
          if (!bindingNames(parent.name).includes("body")) report(call, `<{${bindingNames(parent.name).join(", ")}}>`, "unread");
          return;
        }
        for (const property of kind.properties) {
          const { local, node: element, aliases } = destructured(parent.name, property);
          if (local === undefined || element === undefined) report(call, `<{${property}} dropped>`, "unread");
          else checkVariable(call, parent, local, element, aliases);
        }
      }
      return;
    }
    if (
      kind.kind === "response" &&
      ts.isBinaryExpression(parent) &&
      parent.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      parent.right === node &&
      ts.isIdentifier(unwrap(parent.left))
    ) {
      const name = (unwrap(parent.left) as ts.Identifier).text;
      checkBinding(call, { name, scope: enclosingFunction(parent), after: parent.end, declaration: parent, aliases: [] });
    }
  };

  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) {
      const kind = calleeKind(context, node.expression);
      if (kind) checkCall(node, kind);
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return findings;
}
