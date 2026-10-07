// End-to-end tests in a real browser against the LOCAL app (website :5173, backend :8000, MongoDB).
// Start the backend with SMTP_HOST empty so sign-ups do not send real emails. Run: npx playwright test
import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  timeout: 120_000,
  expect: { timeout: 15_000 },
  fullyParallel: false, // scans hit real websites: one at a time
  workers: 1,
  reporter: [["list"]],
  use: {
    baseURL: process.env.E2E_BASE_URL || "http://localhost:5173",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
