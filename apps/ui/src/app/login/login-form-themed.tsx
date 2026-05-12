"use client";

import { useActionState } from "react";
import { login } from "@/app/login/actions";
import type { LoginFormState } from "@/types";
import styles from "./login.module.css";

interface ThemedLoginFormProps {
  csrfToken: string;
}

export function ThemedLoginForm({ csrfToken }: ThemedLoginFormProps) {
  const [state, formAction, isPending] = useActionState<LoginFormState, FormData>(
    login,
    {}
  );

  return (
    <form action={formAction} noValidate>
      <input type="hidden" name="csrf" value={csrfToken} />

      <div className={styles.fieldGroup}>
        <label className={styles.fieldLabel} htmlFor="sb-user">
          User
        </label>
        <input
          id="sb-user"
          className={styles.fieldInput}
          name="user"
          type="text"
          autoComplete="username"
          defaultValue="sarachen"
        />
      </div>

      <div className={styles.fieldGroup}>
        <label className={styles.fieldLabel} htmlFor="sb-password">
          Password
        </label>
        <input
          id="sb-password"
          className={styles.fieldInput}
          name="password"
          type="password"
          autoComplete="current-password"
          placeholder="••••••••••••"
          aria-describedby={state.error !== undefined ? "sb-password-error" : undefined}
          required
        />
      </div>

      {state.error !== undefined && (
        <p id="sb-password-error" className={styles.errorText} role="alert">
          {state.error}
        </p>
      )}

      <button type="submit" className={styles.loginBtn} disabled={isPending}>
        {isPending ? "AUTHENTICATING…" : "AUTHENTICATE →"}
      </button>

      <div className={styles.footer}>
        Security Buddy &nbsp;·&nbsp; v0.1.0-alpha
      </div>
    </form>
  );
}
