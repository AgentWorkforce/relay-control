import { readSecret,type Env } from "../../src/config.js";
import { S3ObjectBackend } from "../../src/admin/credential-blobs.js";
import type { CloudObjectReader } from "../cloud-import/credentials.js";

type Fetch = (input:string,init:RequestInit) => Promise<Response>;

/** Explicit approved Cloud R2 inputs only; no ambient AWS credential chain.
 * The verifier receives GET only, and redirects/mutations are refused. */
export function readOnlyCloudCredentials(env:Env,fetchImpl:Fetch=(input,init) => fetch(input,init)):CloudObjectReader {
  const required=(name:string) => {
    const value=readSecret(env,name);
    if (!value) throw new Error("Missing Cloud credential reader input");
    return value;
  };
  const endpoint=new URL(required("CLOUD_CREDENTIAL_R2_ENDPOINT"));
  if (endpoint.protocol !== "https:" || endpoint.username || endpoint.password || endpoint.search || endpoint.hash
    || env.NODE_TLS_REJECT_UNAUTHORIZED === "0") throw new Error("Cloud credential reader requires verified HTTPS");
  const backend=new S3ObjectBackend({
    bucket:required("CLOUD_CREDENTIAL_R2_BUCKET"),region:"auto",prefix:"credentials",
    endpoint:endpoint.href,forcePathStyle:true,
    credentials:{accessKeyId:required("CLOUD_CREDENTIAL_R2_ACCESS_KEY_ID"),
      secretAccessKey:required("CLOUD_CREDENTIAL_R2_SECRET_ACCESS_KEY")},
  },async (input,init) => {
    if (init.method !== "GET") throw new Error("Cloud credential reader is read-only");
    return fetchImpl(input,{...init,redirect:"error",signal:AbortSignal.timeout(30000)});
  });
  return Object.freeze({get:(key:string) => backend.get(key)});
}
