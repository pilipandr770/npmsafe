# PRD: npmsafe

## Проблема
Зловмисні оновлення в npm-пакетах (supply-chain атаки) часто проходять повз `npm audit`.

## Ціль
CLI/бібліотека, що перевіряє пакети до інсталяції, інтегрується в локальний флоу і CI.

## MVP обсяг
- Парсер JS (AST) + евристики
- Перевірка scripts (`postinstall`, …)
- Простий ризик-скоринг: safe/suspicious/malicious
- CLI + JSON-вивід; exit-codes (0/1/2)

## DoD
- Тести на набір зразків (benign/malicious)
- Документація README
- Приклади інтеграції в CI та pre-install wrapper