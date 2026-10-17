import { defineConfig, devices } from '@playwright/test';

const pythonCommand = `"${process.env.E2E_BACKEND_PYTHON ?? 'python'}"`;
const backendCommand = `${pythonCommand} -m alembic upgrade head && ${pythonCommand} -m uvicorn app.main:app --host 127.0.0.1 --port 8010`;

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: 'http://127.0.0.1:5174',
    trace: 'retain-on-failure',
    ...devices['Desktop Chrome'],
  },
  webServer: [
    {
      command: backendCommand,
      cwd: '../backend',
      url: 'http://127.0.0.1:8010/health',
      reuseExistingServer: false,
      timeout: 60_000,
      env: {
        DEVPILOT_DATABASE_URL: 'sqlite:///./.e2e.db',
        DEVPILOT_JWT_SECRET: 'e2e-only-secret-with-more-than-32-bytes',
        DEVPILOT_FRONTEND_ORIGIN: 'http://127.0.0.1:5174',
      },
    },
    {
      command: 'npm run dev -- --host 127.0.0.1 --port 5174',
      url: 'http://127.0.0.1:5174',
      reuseExistingServer: false,
      timeout: 60_000,
      env: { VITE_API_PROXY: 'http://127.0.0.1:8010' },
    },
  ],
});
