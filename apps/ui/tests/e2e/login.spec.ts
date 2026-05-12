/**
 * E2E tests for the login gate.
 *
 * Deferred: these tests require a running Next.js server AND a valid
 * OPERATOR_PASSWORD + SESSION_SECRET environment.
 * Run during integration verification (Slice 0 DoD) with:
 *
 *   OPERATOR_PASSWORD=test-password-1234 \
 *   SESSION_SECRET=$(openssl rand -hex 32) \
 *   pnpm test:e2e
 *
 * The server must be started beforehand with `pnpm dev` or `pnpm start`.
 */

import { test, expect } from "@playwright/test";

const BASE_URL = process.env["PLAYWRIGHT_BASE_URL"] ?? "http://localhost:3000";
const OPERATOR_PASSWORD = process.env["OPERATOR_PASSWORD"] ?? "test-password-1234";

test.describe("Login gate", () => {
  test("unauthenticated request to / redirects to /login", async ({ page }) => {
    // Clear any existing cookies
    await page.context().clearCookies();

    await page.goto(`${BASE_URL}/`);
    await expect(page).toHaveURL(/\/login/);
  });

  test("login page renders the sign-in form", async ({ page }) => {
    await page.goto(`${BASE_URL}/login`);
    await expect(page.getByRole("heading", { name: /operator sign-in/i })).toBeVisible();
    await expect(page.getByLabel(/password/i)).toBeVisible();
    await expect(page.getByRole("button", { name: /sign in/i })).toBeVisible();
  });

  test("wrong password shows error and stays on /login", async ({ page }) => {
    await page.goto(`${BASE_URL}/login`);
    await page.getByLabel(/password/i).fill("definitely-wrong-password");
    await page.getByRole("button", { name: /sign in/i }).click();

    // Should remain on /login
    await expect(page).toHaveURL(/\/login/);
    // Should show an error message
    await expect(page.getByRole("alert")).toBeVisible();
  });

  test("correct password redirects to dashboard", async ({ page }) => {
    await page.goto(`${BASE_URL}/login`);
    await page.getByLabel(/password/i).fill(OPERATOR_PASSWORD);
    await page.getByRole("button", { name: /sign in/i }).click();

    // Should land on the dashboard
    await expect(page).toHaveURL(`${BASE_URL}/`);
    await expect(page.getByRole("heading", { name: /security buddy/i })).toBeVisible();
  });

  test("authenticated user visiting /login is redirected to /", async ({ page }) => {
    // First log in
    await page.goto(`${BASE_URL}/login`);
    await page.getByLabel(/password/i).fill(OPERATOR_PASSWORD);
    await page.getByRole("button", { name: /sign in/i }).click();
    await expect(page).toHaveURL(`${BASE_URL}/`);

    // Now navigate to /login again
    await page.goto(`${BASE_URL}/login`);
    await expect(page).toHaveURL(`${BASE_URL}/`);
  });

  test("sign out clears session and redirects to /login", async ({ page }) => {
    // Log in first
    await page.goto(`${BASE_URL}/login`);
    await page.getByLabel(/password/i).fill(OPERATOR_PASSWORD);
    await page.getByRole("button", { name: /sign in/i }).click();
    await expect(page).toHaveURL(`${BASE_URL}/`);

    // Click sign out
    await page.getByRole("button", { name: /sign out/i }).click();
    await expect(page).toHaveURL(/\/login/);

    // Navigating to / should redirect back to /login
    await page.goto(`${BASE_URL}/`);
    await expect(page).toHaveURL(/\/login/);
  });
});
