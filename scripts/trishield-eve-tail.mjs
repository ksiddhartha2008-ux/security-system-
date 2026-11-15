#!/usr/bin/env node
/**
 * Suricata EVE JSON tailer for SecureFlow TriShield.
 *
 * It reads EVE records from a file, keeps a byte offset so a restart does not
 * replay old events, and posts batches to the collector ingestion endpoint with
 * the collector bearer token. It never needs a session and never talks to the
 * database directly.
 *
 *   node scripts/trishield-eve-tail.mjs \
 *     --file /var/log/suricata/eve.json \
 *     --url https://secureflow.example \
 *     --token tsk_xxx \
 *     --follow
 *
 * Options:
 *   --file <path>        EVE JSON file (required unless --stdin)
 *   --stdin              read records from standard input and exit at EOF
 *   --url <base>         API base URL, for example https://secureflow.example
 *   --token <tsk_...>    collector token created in the TriShield page
 *   --follow             keep polling the file for new lines
 *   --once               read what is there now and exit (default with --stdin)
 *   --all                send every event type, not only alerts
 *   --batch <n>          records per request, default 50
 *   --offset-file <path> offset state, default <file>.trishield-offset
 *   --dry-run            print batches without sending them
 */
import { createReadStream, existsSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline';

function parseArgs(argv) {
  const args = { batch: 50, all: false, follow: false, once: false, stdin: false, dryRun: false };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    const next = () => argv[++i];
    if (token === '--file') args.file = next();
    else if (token === '--url') args.url = next();
    else if (token === '--token') args.token = next();
    else if (token === '--offset-file') args.offsetFile = next();
    else if (token === '--batch') args.batch = Math.max(1, Number(next()) || 50);
    else if (token === '--follow') args.follow = true;
    else if (token === '--once') args.once = true;
    else if (token === '--stdin') args.stdin = true;
    else if (token === '--all') args.all = true;
    else if (token === '--dry-run') args.dryRun = true;
    else if (token === '--help' || token === '-h') args.help = true;
    else throw new Error(`Unknown argument: ${token}`);
  }
  return args;
}

function usage() {
  console.log('Usage: node scripts/trishield-eve-tail.mjs --file <eve.json> --url <base> --token <tsk_...> [--follow] [--all] [--batch 50] [--dry-run]');
}

function normalise(record) {
  if (!record || typeof record !== 'object') return null;
  if (!record.event_type && !record.alert) return null;
  if (!record.timestamp && !record.flow?.start) return null;
  const type = String(record.event_type ?? 'alert');
  return { ...record, event_type: type };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) { usage(); return 0; }
  if (!args.stdin && !args.file) throw new Error('Provide --file or --stdin');
  if (!args.dryRun && !args.url) throw new Error('Provide --url (or use --dry-run)');
  if (!args.dryRun && !args.token) throw new Error('Provide --token (or use --dry-run)');
  if (args.url && !/^https?:\/\//i.test(args.url)) throw new Error('--url must start with http:// or https://');
  if (args.token && !/^tsk_[A-Za-z0-9_-]+$/.test(args.token)) throw new Error('--token must look like tsk_...');

  const endpoint = `${String(args.url ?? '').replace(/\/+$/, '')}/api/trishield/ingest/suricata`;
  const offsetFile = args.offsetFile ?? (args.file ? `${args.file}.trishield-offset` : null);
  let offset = 0;
  if (offsetFile && existsSync(offsetFile)) {
    const stored = Number(readFileSync(offsetFile, 'utf8').trim());
    if (Number.isFinite(stored) && stored >= 0) offset = stored;
  }

  let batch = [];
  let sent = 0;
  let skipped = 0;

  const flush = async () => {
    if (!batch.length) return;
    const payload = batch;
    batch = [];
    if (args.dryRun) {
      console.log(`[dry-run] ${payload.length} record(s): ${payload.map((row) => row.event_type).join(', ')}`);
    } else {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${args.token}` },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(15_000),
      });
      const text = await response.text();
      if (!response.ok) {
        throw new Error(`Ingestion failed with HTTP ${response.status}: ${text.slice(0, 300)}`);
      }
      let accepted = payload.length;
      try { accepted = JSON.parse(text)?.data?.accepted ?? payload.length; } catch { /* keep batch size */ }
      sent += accepted;
      console.log(`[eve] sent ${payload.length}, accepted ${accepted}`);
    }
    if (offsetFile) writeFileSync(offsetFile, String(offset));
  };

  const handleLine = async (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    let record;
    try { record = JSON.parse(trimmed); } catch { skipped += 1; return; }
    const normalised = normalise(record);
    if (!normalised) { skipped += 1; return; }
    if (!args.all && normalised.event_type !== 'alert') { skipped += 1; return; }
    batch.push(normalised);
    if (batch.length >= args.batch) await flush();
  };

  const readFrom = async (start) => {
    const stream = createReadStream(args.file, { start, encoding: 'utf8' });
    const lines = createInterface({ input: stream, crlfDelay: Infinity });
    let bytes = start;
    for await (const line of lines) {
      bytes += Buffer.byteLength(`${line}\n`, 'utf8');
      offset = bytes;
      await handleLine(line);
    }
    await flush();
    return bytes;
  };

  if (args.stdin) {
    const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
    for await (const line of lines) await handleLine(line);
    await flush();
  } else {
    const size = statSync(args.file).size;
    if (offset > size) {
      console.warn('[eve] offset is beyond the file size, assuming rotation; starting from 0');
      offset = 0;
    }
    offset = await readFrom(offset);
    if (args.follow && !args.once) {
      console.log(`[eve] following ${args.file} from byte ${offset}`);
      for (;;) {
        await new Promise((resolve) => setTimeout(resolve, 1000));
        let current = 0;
        try { current = statSync(args.file).size; } catch { continue; }
        if (current < offset) { offset = 0; }
        if (current > offset) offset = await readFrom(offset);
      }
    }
  }

  console.log(`[eve] done: accepted ${sent}, skipped ${skipped}`);
  return 0;
}

main()
  .then((code) => { process.exitCode = code; })
  .catch((error) => {
    console.error(`[eve] ${error.message}`);
    process.exitCode = 1;
  });
