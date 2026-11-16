import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { closeSync, openSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer } from "node:net";
import { setTimeout as delay } from "node:timers/promises";
import { Client } from "pg";

const here = dirname(fileURLToPath(import.meta.url));
const directory = await mkdtemp(join(tmpdir(), "cloud-verify-"));
const data = join(directory,"data");
const log = join(directory,"postgres.log");
const pgBinary = (name: string) => process.env.CLOUD_VERIFY_PG_BIN ? join(process.env.CLOUD_VERIFY_PG_BIN,name) : name;
let postgres: ChildProcess | undefined;
let testProcess: ChildProcess | undefined;
let interrupted = false;
for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => { interrupted = true; testProcess?.kill(signal); postgres?.kill("SIGTERM"); });
}

async function unusedPort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve,reject) => {
    server.once("error",reject);
    server.listen(0,"127.0.0.1",resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("port_unavailable");
  await new Promise<void>((resolve,reject) => server.close((e) => e ? reject(e) : resolve()));
  return address.port;
}

try {
  const args=process.argv.slice(2);
  let reportPath:string|undefined,manifestPath:string|undefined,testPattern:string|undefined;
  while (args.length) {
    const flag=args.shift(),value=args.shift();
    if (!value || value.startsWith("--")) throw new Error("output_path_required");
    if (flag === "--report" && !reportPath) reportPath=value;
    else if (flag === "--write-schema-manifest" && !manifestPath) manifestPath=value;
    else if (flag === "--test-pattern" && !testPattern) {new RegExp(value);testPattern=value;}
    else throw new Error("unknown_or_duplicate_argument");
  }
  // No Docker, shared databases, npm installs or parallel test workers.
  const init = spawnSync(pgBinary("initdb"), ["-D",data,"-U","cloud_verify_fixture","--auth-local=trust","--auth-host=trust","--no-locale","--encoding=UTF8"],
    { encoding: "utf8", maxBuffer: 1024*1024 });
  if (init.status !== 0) throw new Error(`initdb_failed${init.error ? `_${(init.error as NodeJS.ErrnoException).code}` : ""}`);
  const port = await unusedPort();
  const fd = openSync(log,"a",0o600);
  postgres = spawn(pgBinary("postgres"), ["-D",data,"-h","127.0.0.1","-p",String(port),
    "-c","unix_socket_directories=", "-c","shared_buffers=16MB", "-c","max_connections=10",
    "-c","work_mem=1MB", "-c","maintenance_work_mem=8MB", "-c","max_parallel_workers=0",
    "-c","fsync=off", "-c","log_statement=none"], { stdio: ["ignore",fd,fd] });
  closeSync(fd);
  // Attach immediately, including an absent postgres executable.
  let serverError: Error | undefined;
  postgres.on("error", (error) => { serverError = error; });
  let ready = false;
  for (let attempt=0;attempt<100 && !interrupted;attempt++) {
    if (serverError || postgres.exitCode !== null) throw new Error("postgres_start_failed");
    const probe = new Client({ host: "127.0.0.1",port,user:"cloud_verify_fixture",database:"postgres",password:"",connectionTimeoutMillis:300 });
    try { await probe.connect(); ready = true; }
    catch { /* The dedicated cluster is still starting. */ }
    finally { await probe.end(); }
    if (ready) break;
    await delay(100);
  }
  if (!ready) throw new Error("postgres_not_ready");
  testProcess = spawn(process.execPath,["--import","tsx","--test","--test-concurrency=1",
    ...(testPattern ? ["--test-name-pattern",testPattern] : []),
    join(here,"../../test/cloud-import-verify.test.ts"),join(here,"../../test/cloud-import-verify-integration.test.ts"),
    join(here,"../../test/cloud-import-verify-readers.test.ts")], {
    cwd:join(here,"../.."), stdio:"inherit",
    env: { ...process.env, CLOUD_VERIFY_FIXTURE_CLUSTER:"synthetic-only", CLOUD_VERIFY_FIXTURE_PORT:String(port),
      CLOUD_VERIFY_IMPORT_REPORT_PATH:reportPath ?? "",CLOUD_VERIFY_SCHEMA_MANIFEST_PATH:manifestPath ?? "" },
  });
  process.exitCode = await new Promise<number>((resolve,reject) => {
    testProcess!.once("error",reject);
    testProcess!.once("exit",(code) => resolve(code ?? 1));
  });
  if (process.exitCode === 0 && reportPath) {
    const report = JSON.parse(await readFile(reportPath,"utf8"));
    if (!report.ok) throw new Error("synthetic_receipt_failed");
    process.stdout.write(`Actual importer synthetic receipt: ${reportPath}\n`);
  }
} catch (error) {
  // Only synthetic data is ever put into this cluster. Log stays local on failure.
  process.stderr.write(`Synthetic dry-run failed (${error instanceof Error ? error.message : "unknown"}). Logs: ${directory}\n`);
  process.exitCode = 2;
} finally {
  if (postgres?.pid && postgres.exitCode === null) {
    const stopped = new Promise<void>((resolve) => postgres!.once("exit",() => resolve()));
    postgres.kill("SIGTERM");
    await stopped;
  }
  if (process.exitCode === 0) await rm(directory,{ recursive:true,force:true });
  else {
    // Check that log exists but do not print potentially verbose PG logs.
    await readFile(log).catch(() => undefined);
    process.stderr.write(`Retained synthetic cluster at ${directory}\n`);
  }
}
