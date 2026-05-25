import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

const dataDir = process.env.CODECANIC_DATA_DIR || join(process.cwd(), ".data");
const dataFile = join(dataDir, "codecanic.json");
const empty = { users: [], organizations: [], memberships: [], sessions: [], connectorCreds: [] };

let writeChain = Promise.resolve();
let cache = null;

async function loadFromDisk() {
  try {
    const raw = await readFile(dataFile, "utf8");
    const parsed = JSON.parse(raw);
    return { ...empty, ...parsed };
  } catch (error) {
    if (error.code === "ENOENT") return { ...empty };
    throw error;
  }
}

export async function read() {
  if (!cache) cache = await loadFromDisk();
  return cache;
}

export async function write(mutator) {
  writeChain = writeChain.then(async () => {
    const current = await read();
    const next = await mutator(current);
    if (!next) return current;
    await mkdir(dirname(dataFile), { recursive: true });
    const tmp = `${dataFile}.${process.pid}.${Date.now()}.tmp`;
    await writeFile(tmp, JSON.stringify(next, null, 2));
    await rename(tmp, dataFile);
    cache = next;
    return next;
  });
  return writeChain;
}

export function resetCache() {
  cache = null;
}
