import { expect, test } from "@playwright/test";
import { cleanup, expectNoOverflow, newEmail, scan, signUp } from "./helpers";

test.afterAll(cleanup);

const VIEWPORTS = { mobile: { width: 390, height: 844 }, tablet: { width: 768, height: 1024 }, desktop: { width: 1280, height: 800 } };

for (const [name, size] of Object.entries(VIEWPORTS)) {
  test(`no horizontal scrolling and everything reachable on ${name} (${size.width}px)`, async ({ page }) => {
    await page.setViewportSize(size);
    for (const path of ["/", "/login", "/signup", "/forgot-password"]) {
      await page.goto(path);
      await expectNoOverflow(page);
    }
    await signUp(page, newEmail());
    await scan(page, "github.com");
    await expect(page.getByRole("heading", { name: "github.com", level: 2, exact: true })).toBeVisible({ timeout: 70_000 });
    await expectNoOverflow(page);
    await expect(page.getByRole("button", { name: "Scan website" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Log out" })).toBeVisible();
    for (const path of ["/history", "/monitoring", "/alerts", "/profile"]) {
      await page.goto(path);
      await expectNoOverflow(page);
    }
  });
}
