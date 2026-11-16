import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtemp,writeFile,rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readOnlyCloudCredentials } from "../scripts/cloud-import-verify/credential-readers.js";

const inputs={CLOUD_CREDENTIAL_R2_ENDPOINT:"https://objects.example.test",CLOUD_CREDENTIAL_R2_BUCKET:"synthetic-fixtures",
  CLOUD_CREDENTIAL_R2_ACCESS_KEY_ID:"SYNTHETIC_ACCESS",CLOUD_CREDENTIAL_R2_SECRET_ACCESS_KEY:"synthetic-secret-only"};

test("Cloud credential reader exposes signed GET only with no redirects",async () => {
  const calls:{url:string;init:RequestInit}[]=[];
  const reader=readOnlyCloudCredentials(inputs,async (url,init) => {calls.push({url,init});return new Response("synthetic-envelope");});
  assert.deepEqual(Object.keys(reader),["get"]);assert.ok(Object.isFrozen(reader));
  assert.equal(await reader.get("user/accounts/row/credentials.json.enc"),"synthetic-envelope");
  assert.equal(calls.length,1);
  assert.equal(calls[0]!.url,"https://objects.example.test/synthetic-fixtures/credentials/user/accounts/row/credentials.json.enc");
  assert.equal(calls[0]!.init.method,"GET");assert.equal(calls[0]!.init.redirect,"error");
  assert.ok(calls[0]!.init.signal instanceof AbortSignal);
  assert.ok(new Headers(calls[0]!.init.headers).get("authorization")!.includes("Credential=SYNTHETIC_ACCESS/"));
});

test("Cloud credential reader uses explicit FILE inputs rather than ambient AWS",async () => {
  const directory=await mkdtemp(join(tmpdir(),"cloud-reader-fixture-"));
  try {
    const env:Record<string,string>={AWS_ACCESS_KEY_ID:"unused-ambient-id",AWS_SECRET_ACCESS_KEY:"unused-ambient-secret"};
    for (const [name,value] of Object.entries(inputs)) {
      const path=join(directory,name);await writeFile(path,value,{mode:0o600});env[`${name}_FILE`]=path;
    }
    let auth="";
    const reader=readOnlyCloudCredentials(env,async (_url,init) => {auth=new Headers(init.headers).get("authorization")!;return new Response(null,{status:404});});
    assert.equal(await reader.get("missing"),null);
    assert.ok(auth.includes("Credential=SYNTHETIC_ACCESS/"));assert.ok(!auth.includes("unused-ambient-id"));
  } finally {await rm(directory,{recursive:true,force:true});}
});

test("Cloud credential reader refuses unsafe endpoints and disabled TLS before fetching",() => {
  let requests=0;
  const fetcher=async () => {requests++;return new Response();};
  for (const endpoint of ["http://objects.example.test","https://user:private@objects.example.test","https://objects.example.test?private=value","https://objects.example.test#private"]) {
    assert.throws(() => readOnlyCloudCredentials({...inputs,CLOUD_CREDENTIAL_R2_ENDPOINT:endpoint},fetcher),/verified HTTPS/);
  }
  assert.throws(() => readOnlyCloudCredentials({...inputs,NODE_TLS_REJECT_UNAUTHORIZED:"0"},fetcher),/verified HTTPS/);
  assert.throws(() => readOnlyCloudCredentials({},fetcher),/Missing Cloud credential reader input/);
  assert.equal(requests,0);
});

test("Cloud credential reader reports HTTP status without object body or endpoint",async () => {
  const marker="synthetic-body-must-stay-private";
  const reader=readOnlyCloudCredentials(inputs,async () => new Response(marker,{status:503}));
  await assert.rejects(reader.get("user/accounts/row/credentials.json.enc"),(error:Error) => {
    assert.match(error.message,/503/);assert.ok(!error.message.includes(marker));
    assert.ok(!error.message.includes("example.test"));return true;
  });
});
