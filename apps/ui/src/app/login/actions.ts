"use server";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { z } from "zod";
import { verifyOperatorPassword } from "@/lib/auth/password";
import { createSessionToken } from "@/lib/auth/session";
import { env } from "@/lib/env";
import type { LoginFormState } from "@/types";

const loginSchema = z.object({
  password: z.string().min(1),
  csrf: z.string().min(1),
});

/**
 * Server action for the login form.
 * - Validates CSRF token against the csrf cookie
 * - Compares password constant-time
 * - On success: sets httpOnly session cookie and redirects to /
 * - On failure: returns generic error after 200ms artificial delay
 */
export async function login(
  _prevState: LoginFormState,
  formData: FormData
): Promise<LoginFormState> {
  const raw = {
    password: formData.get("password"),
    csrf: formData.get("csrf"),
  };

  const parsed = loginSchema.safeParse(raw);
  if (!parsed.success) {
    // 200ms delay on all failures to slow brute force
    await new Promise((resolve) => setTimeout(resolve, 200));
    return { error: "Invalid credentials" };
  }

  const { password, csrf } = parsed.data;

  // Validate CSRF token — must match the csrf cookie set on GET /login
  const cookieStore = await cookies();
  const csrfCookie = cookieStore.get("sb_csrf")?.value;
  if (csrfCookie === undefined || csrfCookie !== csrf) {
    await new Promise((resolve) => setTimeout(resolve, 200));
    return { error: "Invalid credentials" };
  }

  const passwordValid = verifyOperatorPassword(password, env.OPERATOR_PASSWORD);

  if (!passwordValid) {
    await new Promise((resolve) => setTimeout(resolve, 200));
    return { error: "Invalid credentials" };
  }

  // Issue session cookie
  const token = createSessionToken(env.SESSION_SECRET);

  cookieStore.set("sb_session", token, {
    httpOnly: true,
    secure: process.env["NODE_ENV"] === "production",
    sameSite: "strict",
    path: "/",
    maxAge: 60 * 60 * 12, // 12 hours
  });

  // Clear CSRF cookie — it was single-use for this login
  cookieStore.delete("sb_csrf");

  redirect("/");
}
