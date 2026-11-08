import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp,writeFile,rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadConfig,readSecret } from "../src/config.js";
import { loadMcpOAuthConfig } from "../src/mcp/oauth/config.js";
import { createMcpOidcIssuer } from "../src/mcp/oauth/oidc.js";

const pair=generateKeyPairSync("rsa",{modulusLength:2048});
const previous=generateKeyPairSync("rsa",{modulusLength:2048});
const key=pair.privateKey.export({type:"pkcs8",format:"pem"}).toString();
const inputs={SELFHOST_MCP_OIDC_SIGNING_KEY_ID:"fake-active",SELFHOST_MCP_OIDC_SIGNING_KEY:key,SELFHOST_MCP_OIDC_SUBJECT_SALT:"fake-stable-salt"};
const load=(env:Record<string,string|undefined>={})=>loadMcpOAuthConfig(env,name=>readSecret(env,name));

test("MCP modules default off in both tenancy modes; connectors and events are independent",()=>{
  for(const tenancy of ["single","multi"]) {
    assert.deepEqual(load({SELFHOST_TENANCY:tenancy}),{enabled:false,eventsEnabled:false,pumpEnabled:false,oidc:null});
    assert.deepEqual(load({SELFHOST_TENANCY:tenancy,SELFHOST_MCP_OAUTH:"on"}),{enabled:true,eventsEnabled:false,pumpEnabled:false,oidc:null});
  }
  assert.equal(load({SELFHOST_MCP_EVENTS:"on"}).enabled,false);
  assert.equal(load({SELFHOST_MCP_EVENTS:"on",SELFHOST_MCP_EVENTS_PUMP:"on"}).pumpEnabled,true);
  assert.throws(()=>load({SELFHOST_MCP_EVENTS_PUMP:"on"}),/requires/);
  for(const name of ["SELFHOST_MCP_OAUTH","SELFHOST_MCP_EVENTS","SELFHOST_MCP_EVENTS_PUMP"]) {
    assert.throws(()=>load({[name]:"true"}),/on or off/);
  }
});

test("OIDC is absent without signing inputs and partial inputs fail instead of advertising unusable keys",()=>{
  assert.equal(load({SELFHOST_MCP_OAUTH:"on"}).oidc,null);
  for(const env of [{SELFHOST_MCP_OIDC_SIGNING_KEY:key},{SELFHOST_MCP_OIDC_SIGNING_KEY_ID:"fake-active"},
    {SELFHOST_MCP_OIDC_SUBJECT_SALT:"fake-salt"},{SELFHOST_MCP_OIDC_PREVIOUS_PUBLIC_KEYS:"[]"}]) {
    assert.throws(()=>load(env),/requires/);
  }
  const config=load({...inputs,SELFHOST_MCP_OAUTH:"on"});
  assert.equal(config.oidc!.keyId,"fake-active");
  assert.deepEqual(createMcpOidcIssuer(config.oidc!).mcpOidcJwks().keys.map(value=>value.kid),["fake-active"]);
});

test("operator key and salt files reuse mutually exclusive secret inputs",async t=>{
  const directory=await mkdtemp(join(tmpdir(),"mcp-config-"));t.after(()=>rm(directory,{recursive:true,force:true}));
  const keyFile=join(directory,"key.pem"),saltFile=join(directory,"salt");
  await writeFile(keyFile,key);await writeFile(saltFile,"fake-stable-salt\n");
  const env={SELFHOST_MCP_OIDC_SIGNING_KEY_ID:"fake-active",SELFHOST_MCP_OIDC_SIGNING_KEY_FILE:keyFile,SELFHOST_MCP_OIDC_SUBJECT_SALT_FILE:saltFile};
  assert.equal(load(env).oidc!.subjectSalt,"fake-stable-salt");
  assert.equal(load(env).oidc!.privateKeyPem,key.trim());
  assert.throws(()=>load({...env,SELFHOST_MCP_OIDC_SIGNING_KEY:key}),/mutually exclusive/);
  assert.throws(()=>load({...env,SELFHOST_MCP_OIDC_SUBJECT_SALT:"fake-other"}),/mutually exclusive/);
});

test("retained OIDC keys must be bounded, public, distinct and correctly typed even when expired",()=>{
  const entry={kid:"fake-previous",publicJwk:previous.publicKey.export({format:"jwk"}),expiresAt:"2026-01-01T00:00:00Z"};
  assert.deepEqual(load({...inputs,SELFHOST_MCP_OIDC_PREVIOUS_PUBLIC_KEYS:JSON.stringify([entry])}).oidc!.previousPublicKeys,[entry]);
  for(const value of [null,{},[entry,entry,entry],[{...entry,kid:7}],[{...entry,expiresAt:7}],
    [{...entry,publicJwk:previous.privateKey.export({format:"jwk"})}],
    [{...entry,kid:inputs.SELFHOST_MCP_OIDC_SIGNING_KEY_ID}],
    [{...entry,publicJwk:pair.publicKey.export({format:"jwk"})}]]) {
    assert.throws(()=>load({...inputs,SELFHOST_MCP_OIDC_PREVIOUS_PUBLIC_KEYS:JSON.stringify(value)}));
  }
  assert.throws(()=>load({...inputs,SELFHOST_MCP_OIDC_PREVIOUS_PUBLIC_KEYS:"not-json"}),/JSON array/);
  assert.throws(()=>load({...inputs,SELFHOST_MCP_OIDC_SIGNING_KEY:"fake-invalid-key"}),/configuration is invalid/);
});

test("application config includes default-off MCP settings without retaining secret values in diagnostics",()=>{
  const env={DATABASE_URL:"postgres://unused",SELFHOST_BOOTSTRAP_TOKEN:"fake-bootstrap-token-at-least-32-bytes",
    SELFHOST_PUBLIC_URL:"https://relay.example.test",RELAYCAST_URL:"http://relaycast.test",
    RELAYCAST_PUBLIC_URL:"https://relaycast.selfhosted.company",RELAYHISTORY_URL:"http://history.test",
    RELAYHISTORY_PUBLIC_URL:"https://history.selfhosted.company",SELFHOST_ENCRYPTION_KEY_ID:"fake-key",SELFHOST_ENCRYPTION_KEY:Buffer.alloc(32,7).toString("base64")};
  assert.deepEqual(loadConfig(env).mcpOAuth,{enabled:false,eventsEnabled:false,pumpEnabled:false,oidc:null});
  const invalid="fake-secret-value-never-echo";
  assert.throws(()=>load({...inputs,SELFHOST_MCP_OIDC_SIGNING_KEY:invalid}),error=>error instanceof Error && !error.message.includes(invalid));
});
