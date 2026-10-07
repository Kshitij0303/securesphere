import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { expect } from "@playwright/test";

const here = path.dirname(fileURLToPath(import.meta.url));
const PYTHON = process.env.E2E_PYTHON || path.join(here, "..", "..", "..", "backend", "venv", "Scripts", "python.exe");
export const PREFIX = "e2e-";

function db(command, value) {
  execFileSync(PYTHON, [path.join(here, "db.py"), command, value], { stdio: "inherit" });
}
export const confirmEmail = (email) => db("verify", email);
export const cleanup = () => db("cleanup", PREFIX);

// A fresh address on a real mail domain (sign-up checks the domain has a mail server). No email is sent.
export const newEmail = () => `${PREFIX}${Date.now()}${Math.floor(Math.random() * 1000)}@gmail.com`;

// Collects console errors and failed API calls; tests assert none happened.
export function watchErrors(page) {
  const errors = [];
  page.on("console", (msg) => msg.type() === "error" && errors.push(`console: ${msg.text()}`));
  page.on("pageerror", (err) => errors.push(`page error: ${err.message}`));
  page.on("response", (res) => res.status() >= 500 && errors.push(`HTTP ${res.status()} ${res.url()}`));
  return errors;
}

export async function signUp(page, email, { confirm = true, name = "E2E Tester" } = {}) {
  await page.goto("/signup");
  await page.getByLabel("Name").fill(name);
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill("password123");
  await page.getByRole("button", { name: "Sign up" }).click();
  await expect(page).toHaveURL(/\/scan$/);
  if (confirm) {
    confirmEmail(email);
    await page.reload();
  }
}

export async function logIn(page, email, password = "password123") {
  await page.goto("/login");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Log in" }).click();
}

export async function scan(page, domain) {
  await page.goto("/scan");
  await page.getByLabel("Domain").fill(domain);
  await page.getByRole("button", { name: "Scan website" }).click();
}

// No horizontal scrolling at this viewport.
export async function expectNoOverflow(page) {
  const { scroll, width } = await page.evaluate(() => ({ scroll: document.documentElement.scrollWidth, width: window.innerWidth }));
  expect(scroll, `page is ${scroll}px wide in a ${width}px window`).toBeLessThanOrEqual(width + 1);
}
