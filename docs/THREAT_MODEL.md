# Threat Model (STRIDE-lite)

Актори:
- атакер, що підміняє пакет/реліз
- атакер зі зламаним акаунтом мейнтейнера

Вектори:
- `postinstall`/`preinstall`
- `child_process.exec*`, `curl | bash`
- обфускація, великі base64
- typosquatting

Пом'якшення:
- статичний аналіз, блокування інсталяції
- репутаційні сигнали (автор/репо)
- підписи (Sigstore) — roadmap