#!/usr/bin/env node

const { program } = require('commander');
const { analyzePackage } = require('../src/analyzer');

const VERSION = '1.0.0';

program
  .name('npmsafe')
  .description('CLI для аналізу npm-пакетів на supply-chain ризики')
  .version(VERSION)
  .argument('<path>', 'Шлях до директорії пакета або package.json')
  .option('-f, --format <format>', 'Формат виводу (json|text)', 'text')
  .option('-v, --verbose', 'Детальний вивід')
  .option('--strict', 'Суворий режим (low/suspicious => exit 2)')
  .action(async (packagePath, options) => {
    try {
      const result = await analyzePackage(packagePath, options);

      if (options.format === 'json') {
        console.log(JSON.stringify(result, null, 2));
      } else {
        printTextReport(result, options.verbose);
      }

      const exitCode = getExitCode(result.risk, options.strict);
      process.exit(exitCode);
    } catch (error) {
      console.error('Помилка:', error.message);
      if (options.verbose) {
        console.error(error.stack);
      }
      process.exit(3);
    }
  });

function printTextReport(result, verbose) {
  console.log(`\n🔍 Аналіз безпеки пакету: ${result.packageName}`);
  console.log(`📊 Рівень ризику: ${getRiskIcon(result.risk)} ${result.risk.toUpperCase()}`);

  if (result.issues.length > 0) {
    console.log('\n⚠️  Виявлені проблеми:');
    result.issues.forEach((issue, index) => {
      console.log(`${index + 1}. ${issue.type}: ${issue.description}`);
      if (verbose && issue.details) {
        console.log(`   Деталі: ${issue.details}`);
      }
      if (issue.location) {
        console.log(`   Розташування: ${issue.location}`);
      }
    });
  } else {
    console.log('\n✅ Проблем не виявлено');
  }

  const stats = result.stats || {};
  const severityCounts = stats.severityCounts || {};
  const typeBreakdown = stats.typeBreakdown || {};
  const totalIssues = stats.totalIssues || 0;

  if (totalIssues > 0) {
    console.log('\n📌 Підсумок ризиків:');
    console.log(`   High: ${severityCounts.high || 0} | Medium: ${severityCounts.medium || 0} | Low: ${severityCounts.low || 0}`);
    const breakdownEntries = Object.entries(typeBreakdown);
    if (breakdownEntries.length > 0) {
      const breakdown = breakdownEntries.map(([type, count]) => `${type}: ${count}`).join(', ');
      console.log(`   За типами: ${breakdown}`);
    }
    if (Array.isArray(stats.topIssues) && stats.topIssues.length > 0) {
      console.log('   Найризикованіші:');
      stats.topIssues.forEach((issue, index) => {
        const location = issue.location ? ` (${issue.location})` : '';
        console.log(`     ${index + 1}. [${issue.severity.toUpperCase()}] ${issue.type || 'unknown'}: ${issue.description}${location}`);
      });
    }
  }

  if (verbose) {
    console.log('\n📈 Статистика:');
    console.log(`   Перевірено файлів: ${stats.filesScanned ?? 0}`);
    console.log(`   Підозрілих скриптів: ${stats.suspiciousScripts ?? 0}`);
    console.log(`   AST-попереджень: ${stats.astWarnings ?? 0}`);
  }
}

function getRiskIcon(risk) {
  switch (risk) {
    case 'safe': return '🟢';
    case 'low': return '🟡';
    case 'suspicious': return '🟠';
    case 'malicious': return '🔴';
    default: return '⚫';
  }
}

function getExitCode(risk, strict) {
  switch (risk) {
    case 'safe': return 0;
    case 'low':
    case 'suspicious':
      return strict ? 2 : 1;
    case 'malicious':
      return 2;
    default:
      return 3;
  }
}

program.parse();
