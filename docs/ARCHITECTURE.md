# Архітектура

- `core/ast` — AST-перевірки (eval, child_process, …)
- `core/meta` — аналіз `package.json` scripts
- `cli` — командний інтерфейс, JSON-вивід
- `integrations` — (roadmap) Semgrep/GuardDog/Snyk/VT/Sigstore
- `score` — агрегація сигналів → рівень ризику