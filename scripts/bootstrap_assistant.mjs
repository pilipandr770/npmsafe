import 'dotenv/config';
import OpenAI from 'openai';
import { readFileSync } from 'fs';
import { readdirSync } from 'fs';
import { join } from 'path';

const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const MODEL = process.env.OPENAI_ASSISTANT_MODEL || 'gpt-4o';

function loadDoc(p) { return readFileSync(p, 'utf8'); }

async function uploadDocsAsFiles(dir) {
  const files = readdirSync(dir, { withFileTypes: true })
    .filter(d => d.isFile())
    .map(d => join(dir, d.name));
  const ids = [];
  for (const f of files) {
    const up = await client.files.create({ file: new Blob([loadDoc(f)], { type: 'text/plain' }), purpose: 'assistants' });
    ids.push(up.id);
  }
  return ids;
}

async function main() {
  console.log('[bootstrap] creating assistant…');
  const sys = loadDoc('prompts/assistant_system.md');

  // Завантажуємо доки у File Search
  const docFiles = [];
  for (const d of ['docs', 'prompts']) {
    const ids = await uploadDocsAsFiles(d);
    docFiles.push(...ids);
  }

  const assistant = await client.assistants.create({
    name: 'npmsafe Dev Assistant',
    instructions: sys,
    model: MODEL,
    tools: [{ type: 'file_search' }]
  });

  // Прив'язуємо файли до асистента (retrieval)
  await client.assistants.update(assistant.id, {
    tool_resources: { file_search: { vector_store_ids: [
      (await client.vectorStores.create({ name: 'npmsafe-docs', file_ids: docFiles })).id
    ]}}
  });

  console.log('[bootstrap] assistant_id =', assistant.id);
  console.log('[bootstrap] Done. Save this ID if потрібно використати напряму.');
}

main().catch(e => { console.error(e); process.exit(1); });