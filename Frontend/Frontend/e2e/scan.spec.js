import { expect, test } from "@playwright/test";
import { cleanup, logIn, newEmail, scan, signUp, watchErrors } from "./helpers";

test.afterAll(cleanup);

test("full journey: scan a real site, read the results, history, log out, log in again", async ({ page }) => {
  const errors = watchErrors(page);
  const email = newEmail();
  await signUp(page, email);
  await expect(page.getByRole("button", { name: /assistant/i })).toHaveCount(0); // appears only after a scan

  await scan(page, "https://GitHub.com/some/path");
  await expect(page.getByText(/Scanning github\.com|Using a scan of github\.com/i)).toBeVisible(); // loading state
  await expect(page.getByRole("heading", { name: "github.com", level: 2, exact: true })).toBeVisible({ timeout: 70_000 });

  // score and grade
  const score = Number(await page.locator("text=out of 100").locator("xpath=preceding-sibling::span").innerText());
  expect(score).toBeGreaterThanOrEqual(90);
  await expect(page.getByText(/^Grade [AB]$/)).toBeVisible();
  // every result card
  for (const card of ["Certificate", "Protocol versions", "Cipher", "Security headers", "HTTPS redirect and cookies",
                      "Known vulnerabilities", "DNS", "What this means"]) {
    await expect(page.getByRole("heading", { name: card, level: 2 })).toBeVisible();
  }
  await expect(page.getByText("TLS 1.0 (outdated)")).toBeVisible();

  // PDF report downloads
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download report (PDF)" }).click();
  expect((await download).suggestedFilename()).toBe("securesphere-report-github.com.pdf");

  // assistant answers from the scan
  await page.getByRole("button", { name: "Open security assistant" }).click();
  await page.getByRole("button", { name: "Why is my score low?" }).click();
  await expect(page.getByRole("dialog")).toContainText("github.com scored");

  // history and the saved report
  await page.getByRole("link", { name: "History" }).click();
  await expect(page.getByRole("cell", { name: "github.com" }).first()).toBeVisible();
  await page.getByRole("link", { name: "View report" }).first().click();
  await expect(page).toHaveURL(/\/scans\/[0-9a-f]{24}$/);
  await expect(page.getByRole("heading", { name: "github.com", level: 2, exact: true })).toBeVisible();

  // log out, log in again: history persists
  await page.getByRole("button", { name: "Log out" }).click();
  await logIn(page, email);
  await page.getByRole("link", { name: "History" }).click();
  await expect(page.getByRole("cell", { name: "github.com" }).first()).toBeVisible();
  await expect(page.getByRole("link", { name: /Profile/ }).first()).toBeVisible();
  expect(errors).toEqual([]);
});

test("bad domains get clear messages", async ({ page }) => {
  await signUp(page, newEmail());
  for (const [domain, message] of [
    ["hello", "Enter a valid domain, like example.com."],
    ["google com", "Enter a valid domain, like example.com."],
    [`no-such-site-${Date.now()}.com`, "doesn't exist. Check the spelling"],
  ]) {
    await scan(page, domain);
    await expect(page.getByRole("alert")).toContainText(message, { timeout: 30_000 });
  }
});

test("monitoring, alerts and profile pages work", async ({ page }) => {
  const errors = watchErrors(page);
  await signUp(page, newEmail(), { name: "Monitor Tester" });
  await page.getByRole("link", { name: "Monitoring" }).click();
  await expect(page.getByText("You are not monitoring any sites yet.")).toBeVisible();
  await page.getByRole("link", { name: "Alerts" }).click();
  await expect(page.getByText("No alerts yet.")).toBeVisible();
  await page.getByRole("link", { name: "Profile", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Monitor Tester" })).toBeVisible();
  await expect(page.getByText("Confirmed")).toBeVisible();
  await page.getByLabel("Name").fill("Renamed Tester");
  await page.getByRole("button", { name: "Save name" }).click();
  await expect(page.getByText("Name updated.")).toBeVisible();
  expect(errors).toEqual([]);
});
