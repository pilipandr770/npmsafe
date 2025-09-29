#!/usr/bin/env node

const { program } = require('commander');
const path = require('path');
const { analyzePackage } = require('../src/analyzer');

program
  .name('npmsafe')
  .description('Утиліта для перевірки npm-пакетів від supply-chain атак')
  .version('1.0.0')
  .argument('<path>', 'Шлях до пакету або package.json')
  .option('-f, --format <format>', 'Формат виводу (json|text)', 'text')
  .option('-v, --verbose', 'Детальний вивід')
  .option('--strict', 'Суворий режим (suspicious = malicious)')
  .action(async (packagePath, options) => {
    try {
      const result = await analyzePackage(packagePath, options);
      
      if (options.format === 'json') {
        console.log(JSON.stringify(result, null, 2));
      } else {
        printTextReport(result, options.verbose);
      }
      
      // Exit codes: 0=safe, 1=suspicious, 2=malicious
      const exitCode = getExitCode(result.risk, options.strict);
      process.exit(exitCode);
      
    } catch (error) {
      console.error('Помилка:', error.message);
      if (options.verbose) {
        console.error(error.stack);
      }
      process.exit(3); // Error exit code
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
  
  if (verbose) {
    console.log('\n📈 Статистика:');
    console.log(`   Перевірено файлів: ${result.stats.filesScanned}`);
    console.log(`   Підозрілих скриптів: ${result.stats.suspiciousScripts}`);
    console.log(`   AST-попереджень: ${result.stats.astWarnings}`);
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
    case 'low': return strict ? 2 : 1;
    case 'suspicious': return strict ? 2 : 1;
    case 'malicious': return 2;
    default: return 3;
  }
}

program.parse();