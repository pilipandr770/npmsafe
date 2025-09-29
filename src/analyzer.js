const fs = require('fs');
const path = require('path');
const { parse } = require('acorn');
const { ancestor: walkAncestor } = require('acorn-walk');
let tsCompiler = null;
try {
  tsCompiler = require('typescript');
} catch (error) {
  tsCompiler = null;
}

const SEVERITY_WEIGHTS = { high: 3, medium: 2, low: 1 };
const normalizeSeverity = (value) => (value && SEVERITY_WEIGHTS[value]) ? value : 'medium';

/**
 * Аналіз пакету на предмет безпеки
 * @param {string} packagePath - Шлях до пакету або package.json
 * @param {object} options - Опції аналізу
 * @returns {Promise<object>} - Результат аналізу
 */
async function analyzePackage(packagePath, options = {}) {
  const packageInfo = await getPackageInfo(packagePath);
  const issues = [];
  const stats = {
    filesScanned: 0,
    suspiciousScripts: 0,
    astWarnings: 0
  };
  
  // Аналіз package.json скриптів
  const scriptIssues = analyzePackageScripts(packageInfo.packageJson);
  issues.push(...scriptIssues);
  stats.suspiciousScripts = scriptIssues.length;
  
  // AST-аналіз JavaScript файлів
  if (packageInfo.jsFiles.length > 0) {
    for (const filePath of packageInfo.jsFiles) {
      const fileIssues = await analyzeJavaScriptFile(filePath, packageInfo.basePath);
      issues.push(...fileIssues);
      stats.filesScanned++;
    }
  }
  
  stats.astWarnings = issues.filter(issue => issue.type === 'ast').length;
  
  // Визначення рівня ризику
  const risk = calculateRisk(issues);

  const severityCounts = { high: 0, medium: 0, low: 0 };
  const typeBreakdown = {};
  issues.forEach(issue => {
    const severity = normalizeSeverity(issue?.severity);
    severityCounts[severity] += 1;
    const typeKey = issue.type || 'unknown';
    typeBreakdown[typeKey] = (typeBreakdown[typeKey] || 0) + 1;
  });

  const topIssues = issues
    .slice()
    .sort((a, b) => SEVERITY_WEIGHTS[normalizeSeverity(b?.severity)] - SEVERITY_WEIGHTS[normalizeSeverity(a?.severity)])
    .slice(0, 3)
    .map(issue => ({
      type: issue.type,
      severity: normalizeSeverity(issue?.severity),
      description: issue.description,
      location: issue.location || null
    }));

  stats.totalIssues = issues.length;
  stats.severityCounts = severityCounts;
  stats.typeBreakdown = typeBreakdown;
  stats.topIssues = topIssues;

  return {
    packageName: packageInfo.packageJson.name || path.basename(packageInfo.basePath),
    version: packageInfo.packageJson.version || 'unknown',
    risk,
    issues,
    stats,
    timestamp: new Date().toISOString()
  };
}

/**
 * Отримання інформації про пакет
 */
async function getPackageInfo(packagePath) {
  const stats = fs.statSync(packagePath);
  let basePath, packageJsonPath;
  
  if (stats.isDirectory()) {
    basePath = packagePath;
    packageJsonPath = path.join(packagePath, 'package.json');
  } else if (path.basename(packagePath) === 'package.json') {
    basePath = path.dirname(packagePath);
    packageJsonPath = packagePath;
  } else {
    throw new Error('Шлях має бути директорією пакету або файлом package.json');
  }
  
  if (!fs.existsSync(packageJsonPath)) {
    throw new Error('Файл package.json не знайдено');
  }
  
  const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
  const jsFiles = findJavaScriptFiles(basePath);
  
  return {
    basePath,
    packageJsonPath,
    packageJson,
    jsFiles
  };
}

/**
 * Пошук JavaScript файлів у пакеті
 */
function findJavaScriptFiles(basePath, maxFiles = 50) {
  const jsFiles = [];
  const excludeDirs = ['node_modules', '.git', 'test', 'tests', '__tests__', 'spec'];
  
  function scanDir(dirPath, depth = 0) {
    if (depth > 3 || jsFiles.length >= maxFiles) return; // Обмеження глибини та кількості
    
    try {
      const items = fs.readdirSync(dirPath);
      for (const item of items) {
        const fullPath = path.join(dirPath, item);
        const stats = fs.statSync(fullPath);
        
        if (stats.isDirectory() && !excludeDirs.includes(item)) {
          scanDir(fullPath, depth + 1);
        } else if (stats.isFile()) {
          const ext = path.extname(item).toLowerCase();
          if (['.js', '.mjs', '.cjs', '.ts', '.tsx'].includes(ext)) {
            jsFiles.push(fullPath);
          }
        }
      }
    } catch (error) {
      // Ігноруємо помилки доступу до файлів
    }
  }
  
  scanDir(basePath);
  return jsFiles;
}

/**
 * Аналіз скриптів у package.json
 */
function analyzePackageScripts(packageJson) {
  const issues = [];
  const scripts = packageJson.scripts || {};
  
  // Підозрілі lifecycle скрипти
  const suspiciousLifecycleScripts = ['postinstall', 'preinstall', 'install', 'prepare'];
  
  for (const [scriptName, scriptContent] of Object.entries(scripts)) {
    if (suspiciousLifecycleScripts.includes(scriptName)) {
      // Перевірка на підозрілі команди
      const dangerousPatterns = [
        { pattern: /curl|wget|fetch/i, description: 'Завантаження файлів з мережі' },
        { pattern: /sh|bash|exec|eval/i, description: 'Виконання shell команд' },
        { pattern: /rm\s+-rf|rmdir/i, description: 'Видалення файлів/директорій' },
        { pattern: /chmod\s+\+x|chmod\s+777/i, description: 'Зміна прав доступу' },
        { pattern: /\/tmp|\/var\/tmp/i, description: 'Робота з тимчасовими директоріями' }
      ];
      
      for (const { pattern, description } of dangerousPatterns) {
        if (pattern.test(scriptContent)) {
          issues.push({
            type: 'script',
            severity: 'high',
            description: `Підозрілий ${scriptName} скрипт: ${description}`,
            details: scriptContent,
            location: `package.json:scripts.${scriptName}`
          });
        }
      }
      
      // Загальне попередження для lifecycle скриптів
      if (issues.length === 0) {
        issues.push({
          type: 'script',
          severity: 'low',
          description: `Lifecycle скрипт ${scriptName} може виконуватися автоматично`,
          details: scriptContent,
          location: `package.json:scripts.${scriptName}`
        });
      }
    }
  }
  
  return issues;
}

/**
 * AST-аналіз JavaScript файлу
 */
async function analyzeJavaScriptFile(filePath, basePath) {
  const issues = [];
  
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const relativePath = path.relative(basePath, filePath);
    const ext = path.extname(filePath).toLowerCase();
    const isTypeScript = ext === '.ts' || ext === '.tsx';
    let parseContent = content;
    let usedTranspiler = false;

    if (isTypeScript) {
      if (!tsCompiler) {
        issues.push({
          type: 'ast',
          severity: 'medium',
          description: 'TypeScript ????, ??? ?????????? typescript ???????? ? ??????????',
          location: relativePath
        });
        return issues;
      }
      try {
        const transpileOptions = {
          compilerOptions: {
            target: tsCompiler.ScriptTarget.ES2022,
            module: tsCompiler.ModuleKind.ESNext,
            jsx: ext === '.tsx' ? tsCompiler.JsxEmit.React : tsCompiler.JsxEmit.None
          },
          fileName: path.basename(filePath)
        };
        parseContent = tsCompiler.transpileModule(content, transpileOptions).outputText;
        usedTranspiler = true;
      } catch (error) {
        issues.push({
          type: 'ast',
          severity: 'medium',
          description: '?? ??????? ????????????? TypeScript',
          details: error.message,
          location: relativePath
        });
        return issues;
      }
    }

    const locationFor = node => {
      const line = node.loc?.start.line;
      if (line && !usedTranspiler) {
        return `${relativePath}:${line}`;
      }
      return relativePath;
    };
    const suspiciousChildProcessMethods = new Set(['exec', 'spawn', 'fork', 'execSync', 'spawnSync', 'execFile', 'execFileSync']);
    const childProcessAliases = new Set();
    const childProcessMethodAliases = new Set();
    const isIdentifier = (candidate, name) => candidate?.type === 'Identifier' && candidate.name === name;
    const isStaticString = argument => {
      if (!argument) return null;
      if (argument.type === 'Literal' && typeof argument.value === 'string') {
        return argument.value;
      }
      if (argument.type === 'TemplateLiteral' && argument.expressions.length === 0) {
        return argument.quasis[0]?.value?.cooked || null;
      }
      return null;
    };
    const isRequireCall = (candidate, moduleName) => {
      if (!candidate || candidate.type !== 'CallExpression') return false;
      if (!isIdentifier(candidate.callee, 'require') || candidate.arguments.length === 0) return false;
      return isStaticString(candidate.arguments[0]) === moduleName;
    };
    const getPropertyName = property => {
      if (!property) return undefined;
      if (property.type === 'Identifier') return property.name;
      if (property.type === 'Literal') return property.value;
      return undefined;
    };
    const extractIdentifierName = pattern => {
      if (!pattern) return undefined;
      if (pattern.type === 'Identifier') return pattern.name;
      if (pattern.type === 'AssignmentPattern' && pattern.left.type === 'Identifier') {
        return pattern.left.name;
      }
      return undefined;
    };
    const registerChildProcessAlias = name => {
      if (name) childProcessAliases.add(name);
    };
    const registerChildProcessMethodAlias = name => {
      if (name) childProcessMethodAliases.add(name);
    };

    // Перевірка розміру файлу (великі файли можуть бути обфускованими)
    if (content.length > 100000) {
      issues.push({
        type: 'ast',
        severity: 'medium',
        description: 'Великий файл (можливо обфускований)',
        location: relativePath
      });
    }

    // Парсинг AST
    const ast = parse(parseContent, { 
      ecmaVersion: 'latest', 
      sourceType: 'module',
      allowReturnOutsideFunction: true,
      allowHashBang: true,
      locations: true
    });

    childProcessAliases.add('child_process');

    // Пошук підозрілих патернів
    walkAncestor(ast, {
      VariableDeclarator(node) {
        if (isRequireCall(node.init, 'child_process')) {
          if (node.id.type === 'Identifier') {
            registerChildProcessAlias(node.id.name);
            issues.push({
              type: 'ast',
              severity: 'high',
              description: 'Імпорт child_process модуля через require()',
              location: locationFor(node)
            });
          } else if (node.id.type === 'ObjectPattern') {
            for (const property of node.id.properties) {
              if (property.type !== 'Property') continue;
              const aliasName = extractIdentifierName(property.value) || (property.key?.name);
              registerChildProcessMethodAlias(aliasName);
            }
            issues.push({
              type: 'ast',
              severity: 'high',
              description: 'Деструктуризація child_process модуля',
              location: locationFor(node)
            });
          }
        }
      },

      AssignmentExpression(node) {
        if (isRequireCall(node.right, 'child_process')) {
          if (node.left.type === 'Identifier') {
            registerChildProcessAlias(node.left.name);
          }
          issues.push({
            type: 'ast',
            severity: 'high',
            description: 'Присвоєння child_process модуля через require()',
            location: locationFor(node)
          });
        }
      },

      ImportDeclaration(node) {
        if (node.source.value === 'child_process') {
          for (const specifier of node.specifiers) {
            if (specifier.type === 'ImportSpecifier') {
              registerChildProcessMethodAlias(specifier.local.name);
            } else if (specifier.local) {
              registerChildProcessAlias(specifier.local.name);
            }
          }
          issues.push({
            type: 'ast',
            severity: 'high',
            description: 'ES6 імпорт child_process модуля',
            location: locationFor(node)
          });
        }
      },

      CallExpression(node, ancestors) {
        if (node.callee.type === 'Identifier' && node.callee.name === 'eval') {
          issues.push({
            type: 'ast',
            severity: 'high',
            description: 'Використання eval() - небезпечно для виконання коду',
            location: locationFor(node)
          });
        }

        if (node.callee.type === 'Identifier' && childProcessMethodAliases.has(node.callee.name)) {
          issues.push({
            type: 'ast',
            severity: 'high',
            description: `Виконання системних команд через ${node.callee.name}()`,
            location: locationFor(node)
          });
        }

        if (isRequireCall(node, 'child_process')) {
          const parent = ancestors[ancestors.length - 2];
          if (!parent || !['VariableDeclarator', 'AssignmentExpression', 'MemberExpression'].includes(parent.type)) {
            issues.push({
              type: 'ast',
              severity: 'high',
              description: 'Імпорт child_process модуля через require()',
              location: locationFor(node)
            });
          }
        }

        if (node.callee.type === 'MemberExpression') {
          const propertyName = getPropertyName(node.callee.property);
          const objectNode = node.callee.object;

          if (isRequireCall(objectNode, 'child_process')) {
            if (propertyName) {
              registerChildProcessMethodAlias(propertyName);
            }
            if (propertyName && suspiciousChildProcessMethods.has(propertyName)) {
              issues.push({
                type: 'ast',
                severity: 'high',
                description: `Виконання системних команд через ${propertyName}()`,
                location: locationFor(node)
              });
            } else {
              issues.push({
                type: 'ast',
                severity: 'high',
                description: 'Імпорт child_process модуля',
                location: locationFor(node)
              });
            }
          }

          if (objectNode.type === 'Identifier' && childProcessAliases.has(objectNode.name)) {
            if (propertyName && suspiciousChildProcessMethods.has(propertyName)) {
              issues.push({
                type: 'ast',
                severity: 'high',
                description: `Виконання системних команд через ${propertyName}()`,
                location: locationFor(node)
              });
            }
          }
        }
      },

      NewExpression(node) {
        if (node.callee.type === 'Identifier' && node.callee.name === 'Function') {
          issues.push({
            type: 'ast',
            severity: 'high',
            description: 'Використання new Function() - динамічне виконання коду',
            location: locationFor(node)
          });
        }
      }
    });

  } catch (error) {
    if (error.name === 'SyntaxError') {
      issues.push({
        type: 'ast',
        severity: 'medium',
        description: 'Не вдається парсити JavaScript (можливо обфускований)',
        details: error.message,
        location: path.relative(basePath, filePath)
      });
    }
  }

  return issues;
}

/**
 * Розрахунок рівня ризику
 */
function calculateRisk(issues) {
  if (!issues || issues.length === 0) {
    return 'safe';
  }

  const counts = { high: 0, medium: 0, low: 0 };
  let totalScore = 0;

  for (const issue of issues) {
    const severity = normalizeSeverity(issue?.severity);
    counts[severity] += 1;
    totalScore += SEVERITY_WEIGHTS[severity];
  }

  if (counts.high >= 2 || totalScore >= 6) {
    return 'malicious';
  }

  if (counts.high >= 1) {
    return 'suspicious';
  }

  if (counts.medium >= 1) {
    return 'suspicious';
  }

  if (totalScore >= 3) {
    return 'suspicious';
  }

  if (totalScore > 0) {
    return 'low';
  }

  return 'safe';
}

module.exports = {
  analyzePackage,
  analyzePackageScripts,
  analyzeJavaScriptFile,
  calculateRisk
};
