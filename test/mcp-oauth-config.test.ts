import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp,writeFile,rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadConfig,readSecret } from "../src/config.js";
import { loadMcpOAuthConfig,mcpOAuthActive } from "../src/mcp/oauth/config.js";
import { createMcpOidcIssuer } from "../src/mcp/oauth/oidc.js";

const pair=generateKeyPairSync("rsa",{modulusLength:2048});
const previous=generateKeyPairSync("rsa",{modulusLength:2048});
const key=pair.privateKey.export({type:"pkcs8",format:"pem"}).toString();
const inputs={SELFHOST_MCP_OIDC_SIGNING_KEY_ID:"fake-active",SELFHOST_MCP_OIDC_SIGNING_KEY:key,SELFHOST_MCP_OIDC_SUBJECT_SALT:"fake-stable-salt"};
const load=(env:Record<string,string|undefined>={})=>loadMcpOAuthConfig(env,name=>readSecret(env,name));

const ON=["on","ON"," On ","true","TRUE","1"],OFF=["off","OFF"," Off ","false","False","0"];

test("connectors default on in both tenancy modes; events stay off and every flag accepts the same spellings",()=>{
  for(const tenancy of ["single","multi"]) {
    const enabled={enabled:true,unavailable:null,eventsEnabled:false,pumpEnabled:false,oidc:null};
    assert.deepEqual(load({SELFHOST_TENANCY:tenancy}),enabled);
    assert.deepEqual(load({SELFHOST_TENANCY:tenancy,SELFHOST_MCP_OAUTH:""}),enabled);
    assert.deepEqual(load({SELFHOST_TENANCY:tenancy,SELFHOST_MCP_OAUTH:"  "}),enabled);
    for(const value of ON) assert.deepEqual(load({SELFHOST_TENANCY:tenancy,SELFHOST_MCP_OAUTH:value}),enabled,value);
    for(const value of OFF) {
      assert.deepEqual(load({SELFHOST_TENANCY:tenancy,SELFHOST_MCP_OAUTH:value}),{...enabled,enabled:false},value);
    }
  }
  for(const value of ON) {
    assert.equal(load({SELFHOST_MCP_EVENTS:value}).eventsEnabled,true,value);
    assert.equal(load({SELFHOST_MCP_EVENTS:"on",SELFHOST_MCP_EVENTS_PUMP:value}).pumpEnabled,true,value);
  }
  for(const value of OFF) {
    assert.equal(load({SELFHOST_MCP_EVENTS:value}).eventsEnabled,false,value);
    assert.equal(load({SELFHOST_MCP_EVENTS:"on",SELFHOST_MCP_EVENTS_PUMP:value}).pumpEnabled,false,value);
  }
  assert.equal(load({SELFHOST_MCP_OAUTH:"off",SELFHOST_MCP_EVENTS:"on"}).enabled,false);
  assert.throws(()=>load({SELFHOST_MCP_EVENTS_PUMP:"on"}),/requires/);
  for(const name of ["SELFHOST_MCP_OAUTH","SELFHOST_MCP_EVENTS","SELFHOST_MCP_EVENTS_PUMP"]) {
    for(const typo of ["yes","no","enabled","2","onn","tru"]) assert.throws(()=>load({[name]:typo}),/must be on or off/,`${name}=${typo}`);
  }
});

test("OIDC is absent without signing inputs; partial or invalid inputs make the flow unavailable instead of failing start-up",()=>{
  assert.equal(load().oidc,null);
  assert.equal(load().unavailable,null);
  const invalid={...inputs,SELFHOST_MCP_OIDC_SIGNING_KEY:"fake-invalid-key"};
  for(const env of [{SELFHOST_MCP_OIDC_SIGNING_KEY:key},{SELFHOST_MCP_OIDC_SIGNING_KEY_ID:"fake-active"},
    {SELFHOST_MCP_OIDC_SUBJECT_SALT:"fake-salt"},{SELFHOST_MCP_OIDC_PREVIOUS_PUBLIC_KEYS:"[]"},invalid]) {
    const config=load(env);
    assert.equal(config.enabled,true);
    assert.equal(config.unavailable?.reason,"oidc_signing_key");
    if(env!==invalid) assert.match(config.unavailable!.detail,/SELFHOST_MCP_OIDC/);
    assert.doesNotMatch(config.unavailable!.detail,/BEGIN|fake-|PRIVATE|MII/);
    assert.equal(config.oidc,null);
    assert.equal(mcpOAuthActive({mcpOAuth:config}),false);
    // Explicitly off: nothing to report.
    assert.equal(load({...env,SELFHOST_MCP_OAUTH:"off"}).unavailable,null);
  }
  const config=load({...inputs,SELFHOST_MCP_OAUTH:"on"});
  assert.equal(config.unavailable,null);
  assert.equal(mcpOAuthActive({mcpOAuth:config}),true);
  assert.equal(config.oidc!.keyId,"fake-active");
  assert.deepEqual(createMcpOidcIssuer(config.oidc!).mcpOidcJwks().keys.map(value=>value.kid),["fake-active"]);
});

test("a public origin the OAuth issuer cannot use makes the flow unavailable",()=>{
  for(const origin of ["http://relay.example.test","https://relay.example.test/base"]) {
    assert.equal(loadMcpOAuthConfig({},()=>undefined,origin).unavailable?.reason,"public_url",origin);
  }
  for(const origin of ["https://relay.example.test","http://localhost:3000","http://127.0.0.1"]) {
    assert.equal(loadMcpOAuthConfig({},()=>undefined,origin).unavailable,null,origin);
  }
  assert.equal(loadMcpOAuthConfig({SELFHOST_MCP_OAUTH:"off"},()=>undefined,"http://relay.example.test").unavailable,null);
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
    assert.equal(load({...inputs,SELFHOST_MCP_OIDC_PREVIOUS_PUBLIC_KEYS:JSON.stringify(value)}).unavailable?.reason,"oidc_signing_key");
  }
  assert.equal(load({...inputs,SELFHOST_MCP_OIDC_PREVIOUS_PUBLIC_KEYS:"not-json"}).unavailable?.reason,"oidc_signing_key");
  assert.equal(load({...inputs,SELFHOST_MCP_OIDC_SIGNING_KEY:"fake-invalid-key"}).unavailable?.reason,"oidc_signing_key");
});

test("application config includes default-on MCP settings without retaining secret values in diagnostics",()=>{
  const env={DATABASE_URL:"postgres://unused",SELFHOST_BOOTSTRAP_TOKEN:"fake-bootstrap-token-at-least-32-bytes",
    SELFHOST_PUBLIC_URL:"https://relay.example.test",RELAYCAST_URL:"http://relaycast.test",
    RELAYCAST_PUBLIC_URL:"https://relaycast.selfhosted.company",RELAYHISTORY_URL:"http://history.test",
    RELAYHISTORY_PUBLIC_URL:"https://history.selfhosted.company",SELFHOST_ENCRYPTION_KEY_ID:"fake-key",SELFHOST_ENCRYPTION_KEY:Buffer.alloc(32,7).toString("base64")};
  assert.deepEqual(loadConfig(env).mcpOAuth,{enabled:true,unavailable:null,eventsEnabled:false,pumpEnabled:false,oidc:null});
  assert.deepEqual(loadConfig({...env,SELFHOST_MCP_OAUTH:"off"}).mcpOAuth,{enabled:false,unavailable:null,eventsEnabled:false,pumpEnabled:false,oidc:null});
  assert.equal(loadConfig({...env,SELFHOST_PUBLIC_URL:"http://relay.example.test"}).mcpOAuth!.unavailable?.reason,"public_url");
  const invalid="fake-secret-value-never-echo";
  const degraded=loadConfig({...env,...inputs,SELFHOST_MCP_OIDC_SIGNING_KEY:invalid}).mcpOAuth!;
  assert.equal(degraded.unavailable?.reason,"oidc_signing_key");
  assert.ok(!JSON.stringify(degraded).includes(invalid));
});


test("review repro: a missing MCP-only signing-key file produces sanitized unavailable mode", async t => {
  const directory = await mkdtemp(join(tmpdir(), "mcp-key-unavailable-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const config = load({
    SELFHOST_MCP_OAUTH: "on",
    SELFHOST_MCP_OIDC_SIGNING_KEY_ID: "fake-key",
    SELFHOST_MCP_OIDC_SIGNING_KEY_FILE: join(directory, "missing-key.pem"),
    SELFHOST_MCP_OIDC_SUBJECT_SALT: "fake-salt",
  });
  assert.ok(config.unavailable);
  assert.equal(config.unavailable.reason, "oidc_signing_key");
  assert.ok(!config.unavailable.detail.includes(directory));
  assert.ok(!config.unavailable.detail.includes("fake-salt"));
});
