/**
 * Empacota o connector num zip pronto pra upload manual no console Lambda
 * (alternativa ao SAM). Gera dist/argos-cloudtrail-connector.zip.
 *
 * Não usa dependências externas além do `zip` do sistema (presente no
 * CloudShell, macOS e Linux). Em Windows, prefira o deploy via SAM.
 */
import { execFileSync } from 'node:child_process';
import { mkdirSync, rmSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const dist = resolve(root, 'dist');
const out = resolve(dist, 'argos-cloudtrail-connector.zip');

rmSync(dist, { recursive: true, force: true });
mkdirSync(dist, { recursive: true });

// Empacota só o conteúdo de src/ (index.mjs + detection.mjs) na raiz do zip.
execFileSync('zip', ['-r', '-j', out, 'src/index.mjs', 'src/detection.mjs'], {
  cwd: root,
  stdio: 'inherit',
});

console.info(`\n✓ Pacote gerado: ${out}`);
console.info('  Handler no console Lambda: index.handler (runtime Node.js 20.x)');
