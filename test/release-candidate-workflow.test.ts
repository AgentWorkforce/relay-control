import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const workflow = readFileSync(
  new URL("../.github/workflows/release-relay-control-image.yml", import.meta.url),
  "utf8",
);

test("release candidate dispatch is bound to the successful main publication", () => {
  const validateJob = workflow.match(/^  validate:\n[\s\S]*?(?=^  publish:)/m)?.[0];
  const publishJob = workflow.match(
    /^  publish:\n[\s\S]*?(?=^  notify-release-candidate:)/m,
  )?.[0];
  const notifyJob = workflow.match(/^  notify-release-candidate:\n[\s\S]*$/m)?.[0];
  assert.ok(validateJob);
  assert.ok(publishJob);
  assert.ok(notifyJob);
  assert.match(validateJob, /      source_sha: \$\{\{ steps\.identity\.outputs\.source_sha \}\}/);
  assert.match(publishJob, /      digest: \$\{\{ steps\.build\.outputs\.digest \}\}/);
  assert.match(notifyJob, /needs: \[validate, publish\]/);
  assert.match(
    notifyJob,
    /if: \$\{\{ needs\.publish\.result == 'success' && github\.ref == 'refs\/heads\/main' \}\}/,
  );
  assert.match(notifyJob, /DIGEST: \$\{\{ needs\.publish\.outputs\.digest \}\}/);
  assert.match(notifyJob, /SOURCE_SHA: \$\{\{ needs\.validate\.outputs\.source_sha \}\}/);
  assert.match(notifyJob, /client_payload\[component\]=relay-control/);
  assert.match(notifyJob, /client_payload\[digest\]=\$DIGEST/);
  assert.match(notifyJob, /client_payload\[source_sha\]=\$SOURCE_SHA/);
  assert.match(notifyJob, /repos\/AgentWorkforce\/infra\/dispatches/);
});
