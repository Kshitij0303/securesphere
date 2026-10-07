import { expect, test } from "@playwright/test";
import { cleanup, newEmail, signUp } from "./helpers";

test.afterAll(cleanup);

// The free backend host sleeps when idle; its first answer can take up to a minute. Simulate that.
test("a slow (waking) server shows a clear banner, and the request still completes", async ({ page }) => {
  await signUp(page, newEmail());
  await page.route("**/history**", async (route) => {
    await new Promise((resolve) => setTimeout(resolve, 6000));
    await route.continue();
  });
  await page.getByRole("link", { name: "History" }).click();
  await expect(page.getByText("The SecureSphere server is waking up")).toBeVisible();
  await expect(page.getByText("You have not scanned any site yet.")).toBeVisible({ timeout: 20_000 });
  await expect(page.getByText("The SecureSphere server is waking up")).toHaveCount(0);
});

test("an unreachable server gives a helpful message, not a generic error", async ({ page }) => {
  await signUp(page, newEmail());
  await page.route("**/history**", (route) => route.abort("connectionrefused"));
  await page.getByRole("link", { name: "History" }).click();
  await expect(page.getByRole("alert")).toContainText("Could not reach the SecureSphere server. It may be starting up");
});
