/**
 * Testa os normalizadores PUROS da varredura de postura (sem AWS SDK — os imports
 * do SDK em scan.mjs são dinâmicos, dentro de runScan). Rode com: node --test
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { sgOpenToWorld, tagName } from '../src/scan.mjs';

test('tagName pega a tag Name', () => {
  assert.equal(tagName([{ Key: 'env', Value: 'prod' }, { Key: 'Name', Value: 'web-01' }]), 'web-01');
  assert.equal(tagName([]), null);
  assert.equal(tagName(undefined), null);
});

test('SSH aberto ao mundo → porta 22', () => {
  const sg = {
    IpPermissions: [
      { IpProtocol: 'tcp', FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: '0.0.0.0/0' }] },
    ],
  };
  assert.deepEqual(sgOpenToWorld(sg), [{ port: 22, protocol: 'tcp', ipv6: false }]);
});

test('todas as portas (proto -1) → all', () => {
  const sg = { IpPermissions: [{ IpProtocol: '-1', IpRanges: [{ CidrIp: '0.0.0.0/0' }] }] };
  assert.deepEqual(sgOpenToWorld(sg), [{ port: 'all', protocol: 'all', ipv6: false }]);
});

test('range pequeno vira portas discretas', () => {
  const sg = {
    IpPermissions: [
      { IpProtocol: 'tcp', FromPort: 20, ToPort: 22, IpRanges: [{ CidrIp: '0.0.0.0/0' }] },
    ],
  };
  const ports = sgOpenToWorld(sg).map((o) => o.port);
  assert.deepEqual(ports, [20, 21, 22]);
});

test('range largo aberto vira all', () => {
  const sg = {
    IpPermissions: [
      { IpProtocol: 'tcp', FromPort: 0, ToPort: 65535, IpRanges: [{ CidrIp: '0.0.0.0/0' }] },
    ],
  };
  assert.deepEqual(sgOpenToWorld(sg), [{ port: 'all', protocol: 'tcp', ipv6: false }]);
});

test('origem restrita (não 0.0.0.0/0) → nada', () => {
  const sg = {
    IpPermissions: [
      { IpProtocol: 'tcp', FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: '10.0.0.0/8' }] },
    ],
  };
  assert.deepEqual(sgOpenToWorld(sg), []);
});

test('só IPv6 ::/0 → marca ipv6', () => {
  const sg = {
    IpPermissions: [
      { IpProtocol: 'tcp', FromPort: 3389, ToPort: 3389, Ipv6Ranges: [{ CidrIpv6: '::/0' }] },
    ],
  };
  assert.deepEqual(sgOpenToWorld(sg), [{ port: 3389, protocol: 'tcp', ipv6: true }]);
});
