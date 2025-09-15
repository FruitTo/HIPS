import { readFile } from 'node:fs/promises'
import { format, parse } from "date-fns";
import path from 'node:path';

// Input
const inp = "15-09-2025";

// Parser
const parsed = parse(inp, "dd-MM-yyyy", new Date())
const day = format(parsed, "dd");
const month = format(parsed, "MM");
const year = format(parsed, "yyyy");

// Find Path
const baseDir = path.resolve("../../alert");
const filePath = baseDir + "/" + year + "/" + month + "/" + day + "/" + inp + ".jsonl"

try {
  const text = await readFile(filePath, 'utf8')
  const arr = text
    .split(/\r?\n/)
    .map(s => s.trim())
    .filter(Boolean)
    .map(JSON.parse);

  console.log(arr.length)
} catch (error) {
  console.log(error)
}
