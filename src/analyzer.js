const fs = require('fs');
const path = require('path');
const { parse } = require('acorn');
const { simple: walkSimple } = require('acorn-walk');

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
        } else if (stats.isFile() && (item.endsWith('.js') || item.endsWith('.mjs'))) {
          jsFiles.push(fullPath);
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
          severity: 'medium',
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
    const ast = parse(content, { 
      ecmaVersion: 2022, 
      sourceType: 'module',
      allowReturnOutsideFunction: true 
    });
    
    // Пошук підозрілих патернів
    walkSimple(ast, {
      CallExpression(node) {
        // eval() виклики
        if (node.callee.name === 'eval') {
          issues.push({
            type: 'ast',
            severity: 'high',
            description: 'Використання eval() - небезпечно для виконання коду',
            location: `${relativePath}:${node.loc?.start.line || '?'}`
          });
        }
        
        // new Function() конструктор
        if (node.callee.type === 'NewExpression' && 
            node.callee.callee && node.callee.callee.name === 'Function') {
          issues.push({
            type: 'ast',
            severity: 'high',
            description: 'Використання new Function() - динамічне виконання коду',
            location: `${relativePath}:${node.loc?.start.line || '?'}`
          });
        }
        
        // child_process методи
        if (node.callee.type === 'MemberExpression') {
          const objectName = node.callee.object.name;
          const propertyName = node.callee.property.name;
          
          if (objectName === 'require' && 
              node.arguments.length > 0 && 
              node.arguments[0].value === 'child_process') {
            issues.push({
              type: 'ast',
              severity: 'high',
              description: 'Імпорт child_process модуля',
              location: `${relativePath}:${node.loc?.start.line || '?'}`
            });
          }
          
          if (['exec', 'spawn', 'fork', 'execSync', 'spawnSync'].includes(propertyName)) {
            issues.push({
              type: 'ast',
              severity: 'high',
              description: `Виконання системних команд через ${propertyName}()`,
              location: `${relativePath}:${node.loc?.start.line || '?'}`
            });
          }
        }
      },
      
      ImportDeclaration(node) {
        // ES6 імпорти child_process
        if (node.source.value === 'child_process') {
          issues.push({
            type: 'ast',
            severity: 'high',
            description: 'ES6 імпорт child_process модуля',
            location: `${relativePath}:${node.loc?.start.line || '?'}`
          });
        }
      }
    });
    
  } catch (error) {
    // Якщо не вдається парсити файл, це може бути підозрілим
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
  if (issues.length === 0) {
    return 'safe';
  }
  
  const highSeverityCount = issues.filter(issue => issue.severity === 'high').length;
  const mediumSeverityCount = issues.filter(issue => issue.severity === 'medium').length;
  
  if (highSeverityCount >= 2) {
    return 'malicious';
  }
  
  if (highSeverityCount >= 1 || mediumSeverityCount >= 3) {
    return 'suspicious';
  }
  
  return 'suspicious';
}

module.exports = {
  analyzePackage,
  analyzePackageScripts,
  analyzeJavaScriptFile,
  calculateRisk
};