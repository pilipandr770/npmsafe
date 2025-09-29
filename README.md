# npmsafe — npm supply-chain guard (prototype)

Мета — зробити легкий інструмент/CLI, що перевіряє npm-пакети **до** інсталяції:
- статичні перевірки JS на ризикові патерни (`eval`, `child_process`, обфускація, великі base64-рядки)
- аналіз `scripts` (`postinstall`, `preinstall`, `prepare`)
- (далі) інтеграції: Semgrep / GuardDog / Snyk / VirusTotal, репутація автора/репо, Sigstore

### Як працювати з ІІ-розробником (Assistants API)
1. Додай `OPENAI_API_KEY` у GitHub Secrets або локально в `.env`.
2. Запусти `npm run bootstrap` — створюється Assistant, у File Search додаються файли з `docs/`, `prompts/`.
3. Запусти `npm run plan` — асистент читає доки і виставляє план задач (вивід у консоль та артефакт CI).
4. Переходимо до задач/PR: користуємось шаблонами з `.github/`.

Документи: див. `docs/PRD.md`, `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`.

> Примітка: OpenAI Codex знято з підтримки. Використовуємо GPT-4o / reasoning-моделі через **Assistants API**.

## Як запускати (локально)

```bash
# Встановити залежності
npm install

# Задати ключ локально
cp .env.example .env
# Відредагуйте .env та встав OPENAI_API_KEY

# Створити асистента й завантажити доки
npm run bootstrap

# Отримати план робіт від асистента
npm run plan
```

> Якщо хочете, щоб це працювало в GitHub Actions — додайте в **Settings → Secrets → Actions** секрет `OPENAI_API_KEY` та увімкніть GitHub Actions у репозиторії.

## Чому не Codex, а Assistants API

* **Codex** офіційно депрекейтед і недоступний у сучасному API. Рекомендовано переходити на GPT-4o/інші моделі.
* **Assistants API** дозволяє тримати інструкції + читати твої файли (File Search) + інструменти. Це зручніше для постійної роботи "ІІ-розробника" у репозиторії.

## Структура проекту

```
npmsafe/
├── docs/                    # Документація для AI асистента
│   ├── PRD.md              # Product Requirements Document
│   ├── ARCHITECTURE.md     # Архітектура системи
│   ├── THREAT_MODEL.md     # Модель загроз
│   └── ROADMAP.md          # План розвитку
├── prompts/                 # Промпти для AI
│   └── assistant_system.md # Системний промпт для асистента
├── scripts/                 # Скрипти для роботи з AI
│   ├── bootstrap_assistant.mjs  # Створення асистента
│   └── run_assistant_plan.mjs   # Отримання плану від асистента
├── .github/                 # GitHub темплейти та workflows
│   ├── ISSUE_TEMPLATE/     # Шаблони issues
│   ├── workflows/          # CI/CD workflows
│   └── PULL_REQUEST_TEMPLATE.md
└── package.json            # Налаштування проекту
```

## Використання в GitHub Actions

Коли ви додаєте `OPENAI_API_KEY` в GitHub Secrets, CI автоматично запускатиме AI асистента для аналізу PR та надання планів розробки. Це дозволяє:

1. **Автоматичний код-ревʼю**: асистент аналізує зміни згідно з документацією
2. **Планування задач**: отримання рекомендацій по декомпозиції feature requests
3. **Архітектурні рішення**: консультації по структурі коду та безпеці

## Робочий процес з AI асистентом

1. **Створіть issue** використовуючи шаблони в `.github/ISSUE_TEMPLATE/`
2. **AI асистент** прочитає ваші доки та запропонує план
3. **Створіть PR** з реалізацією
4. **CI запустить аналіз** та надасть фідбек
5. **Ітеративно покращуйте** згідно з рекомендаціями

## Налаштування моделей

У `.env` можна налаштувати різні моделі OpenAI:

- `OPENAI_ASSISTANT_MODEL=gpt-4o` - для швидкого кодування
- `OPENAI_REASONING_MODEL=o4-mini` - для архітектурного аналізу
- Також підтримуються `gpt-4-turbo`, `gpt-3.5-turbo` та інші
