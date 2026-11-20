#!/usr/bin/env node
/**
 * `tp-workspace` CLI — TP 1.0 Shared Cognitive Space Server & Demo Runner
 */

import { TpWorkspaceHttpServer } from "./workspace.mjs";
import { runTpWorkspaceDemo } from "./demo.mjs";

const USAGE = `Usage:
  tp-workspace demo
  tp-workspace serve [--port <port>] [--host <host>]
`;

function getFlag(argv, flag) {
  const idx = argv.indexOf(flag);
  if (idx >= 0 && idx + 1 < argv.length) {
    return argv[idx + 1];
  }
  return undefined;
}

export async function runTpWorkspaceCli(argv = process.argv.slice(2)) {
  const cmd = argv[0];
  if (!cmd || cmd === "--help" || cmd === "-h" || cmd === "help") {
    console.log(USAGE);
    return 0;
  }

  if (cmd === "demo") {
    await runTpWorkspaceDemo();
    return 0;
  }

  if (cmd === "serve") {
    const port = Number(getFlag(argv, "--port") ?? "0");
    const host = getFlag(argv, "--host") ?? "127.0.0.1";
    const srv = new TpWorkspaceHttpServer({ host, port });
    const origin = await srv.start();
    console.log(JSON.stringify({ status: "listening", origin }));
    process.on("SIGINT", () => {
      srv.stop().then(() => process.exit(0));
    });
    return 0;
  }

  console.error(`Unknown command: ${cmd}`);
  console.error(USAGE);
  return 1;
}

const isMain =
  process.argv[1] &&
  (process.argv[1].endsWith("/src/cli.mjs") ||
    process.argv[1].endsWith("\\src\\cli.mjs") ||
    process.argv[1].endsWith("tp-workspace"));

if (isMain) {
  runTpWorkspaceCli().then(
    (code) => {
      if (code !== 0) process.exitCode = code;
    },
    (err) => {
      console.error(err instanceof Error ? err.message : String(err));
      process.exitCode = 1;
    }
  );
}
