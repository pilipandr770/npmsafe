import 'dotenv/config';
import OpenAI from 'openai';
import { readFileSync } from 'fs';

const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const MODEL = process.env.OPENAI_ASSISTANT_MODEL || 'gpt-4o';

async function ensureAssistant() {
  // Спрощено: щоразу створюємо тимчасового асистента з File Search (для CI)
  const sys = readFileSync('prompts/assistant_system.md', 'utf8');
  const assistant = await client.assistants.create({
    name: 'npmsafe Dev Assistant (CI)',
    instructions: sys,
    model: MODEL,
    tools: [{ type: 'file_search' }]
  });
  return assistant;
}

async function attachDocs(assistantId) {
  const { id: vsId } = await client.vectorStores.create({ name: 'npmsafe-docs' });
  const uploads = [];
  for (const p of ['docs/PRD.md','docs/ARCHITECTURE.md','docs/THREAT_MODEL.md','docs/ROADMAP.md']) {
    const file = await client.files.create({ file: new Blob([readFileSync(p,'utf8')], { type: 'text/plain' }), purpose: 'assistants' });
    uploads.push(file.id);
  }
  await client.vectorStores.fileBatches.create(vsId, { file_ids: uploads });
  await client.assistants.update(assistantId, { tool_resources: { file_search: { vector_store_ids: [vsId] }}});
}

async function main() {
  const assistant = await ensureAssistant();
  await attachDocs(assistant.id);

  const thread = await client.threads.create({
    messages: [{ role: 'user', content: `
Прочитай PRD/ARCHITECTURE/THREAT_MODEL та запропонуй:
1) декомпозицію на епіки/таски на 2 спринти,
2) MVP-план і критерії приймання,
3) список ризиків та як їх тестувати,
4) перший PR: структура коду (CLI + core) з мок-тестом.
Відповідай стисло у Markdown-таблицях.
`}]
  });

  const run = await client.threads.runs.create(thread.id, { assistant_id: assistant.id });
  let status = run.status;
  while (!['completed','failed','cancelled','expired'].includes(status)) {
    await new Promise(r => setTimeout(r, 1500));
    const r2 = await client.threads.runs.retrieve(thread.id, run.id);
    status = r2.status;
  }
  if (status !== 'completed') throw new Error('Assistant run did not complete: ' + status);

  const msgs = await client.threads.messages.list(thread.id);
  const last = msgs.data[0]?.content?.map(c => c.text?.value || '').join('\n') || '(no output)';
  console.log('\n===== Assistant Plan =====\n');
  console.log(last);
}

main().catch(e => { console.error(e); process.exit(1); });