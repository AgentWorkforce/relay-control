import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const workflow = readFileSync(
  new URL("../.github/workflows/release-relay-control-image.yml", import.meta.url),
  "utf8",
);

test("release candidate dispatch is bound to the successful main publication", () => {
  assert.match(workflow, /needs: \[validate, publish\]/);
  assert.match(
    workflow,
    /if: \$\{\{ needs\.publish\.result == 'success' && github\.ref == 'refs\/heads\/main' \}\}/,
  );
  assert.match(workflow, /DIGEST: \$\{\{ needs\.publish\.outputs\.digest \}\}/);
  assert.match(workflow, /SOURCE_SHA: \$\{\{ needs\.validate\.outputs\.source_sha \}\}/);
  assert.match(workflow, /client_payload\[component\]=relay-control/);
  assert.match(workflow, /client_payload\[digest\]=\$DIGEST/);
  assert.match(workflow, /client_payload\[source_sha\]=\$SOURCE_SHA/);
  assert.match(workflow, /repos\/AgentWorkforce\/infra\/dispatches/);
});
