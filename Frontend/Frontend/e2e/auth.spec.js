import { expect, test } from "@playwright/test";
import { cleanup, logIn, newEmail, signUp, watchErrors } from "./helpers";

test.afterAll(cleanup);

test("landing page loads with logo, and protected pages send visitors to log in", async ({ page }) => {
  const errors = watchErrors(page);
  await page.goto("/");
  await expect(page.getByRole("img", { name: "SecureSphere" })).toBeVisible();
  await expect(page.getByRole("heading", { level: 1 })).toContainText("HTTPS");
  for (const path of ["/scan", "/history", "/monitoring", "/alerts", "/profile"]) {
    await page.goto(path);
    await expect(page).toHaveURL(/\/login$/);
  }
  await expect(page.getByRole("button", { name: /assistant/i })).toHaveCount(0); // no chat when logged out
  expect(errors).toEqual([]);
});

test("sign-up form rejects bad input with clear messages", async ({ page }) => {
  await page.goto("/signup");
  const submit = page.getByRole("button", { name: "Sign up" });
  await submit.click();
  await expect(page.getByRole("alert")).toHaveText("Enter your name.");
  await page.getByLabel("Name").fill("Tester");
  await page.getByLabel("Email").fill("not-an-email");
  await submit.click();
  await expect(page.getByRole("alert")).toHaveText("Enter a valid email address.");
  await page.getByLabel("Email").fill("someone@gnail.com");
  await expect(page.getByText("Did you mean")).toContainText("someone@gmail.com"); // typo hint
  await page.getByRole("button", { name: "someone@gmail.com" }).click();
  await expect(page.getByLabel("Email")).toHaveValue("someone@gmail.com");
  await page.getByLabel("Password").fill("short");
  await submit.click();
  await expect(page.getByRole("alert")).toHaveText("Password must be at least 8 characters.");
});

test("sign-up refuses an email domain with no mail server, and a duplicate email", async ({ page }) => {
  await page.goto("/signup");
  await page.getByLabel("Name").fill("Tester");
  await page.getByLabel("Email").fill(`e2e-${Date.now()}@f.com`);
  await page.getByLabel("Password").fill("password123");
  await page.getByRole("button", { name: "Sign up" }).click();
  await expect(page.getByRole("alert")).toContainText("can't send email to f.com");

  const email = newEmail();
  await signUp(page, email, { confirm: false });
  await page.getByRole("button", { name: "Log out" }).click();
  await page.goto("/signup");
  await page.getByLabel("Name").fill("Again");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill("password123");
  await page.getByRole("button", { name: "Sign up" }).click();
  await expect(page.getByRole("alert")).toHaveText("This email is already registered");
});

test("unconfirmed account sees the banner and cannot scan", async ({ page }) => {
  await signUp(page, newEmail(), { confirm: false });
  await expect(page.getByText("Please confirm your email address")).toBeVisible();
  await page.getByLabel("Domain").fill("github.com");
  await page.getByRole("button", { name: "Scan website" }).click();
  await expect(page.getByRole("alert")).toContainText("confirm your email address first");
});

test("login errors, successful login, and logout clears the session", async ({ page }) => {
  const errors = watchErrors(page);
  const email = newEmail();
  await signUp(page, email);
  await page.getByRole("button", { name: "Log out" }).click();
  await expect(page).toHaveURL(/\/login$/);
  expect(await page.evaluate(() => localStorage.getItem("token"))).toBeNull();

  await logIn(page, email, "wrongpassword");
  await expect(page.getByRole("alert")).toHaveText("Incorrect email or password");
  await logIn(page, `nobody-${Date.now()}@gmail.com`);
  await expect(page.getByRole("alert")).toHaveText("Incorrect email or password");
  await logIn(page, email);
  await expect(page).toHaveURL(/\/scan$/);
  await expect(page.getByRole("link", { name: "Your profile" })).toBeVisible();

  await page.getByRole("button", { name: "Log out" }).click();
  await page.goto("/history");
  await expect(page).toHaveURL(/\/login$/); // protected page after logout
  expect(errors.filter((e) => !e.includes("401"))).toEqual([]);
});

test("an expired or invalid session sends the user back to log in", async ({ page }) => {
  await signUp(page, newEmail());
  await page.evaluate(() => localStorage.setItem("token", "invalid.token.value"));
  await page.goto("/history");
  await expect(page).toHaveURL(/\/login$/);
});
