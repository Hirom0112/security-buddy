"use client";

import { useActionState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { login } from "@/app/login/actions";
import type { LoginFormState } from "@/types";

const loginSchema = z.object({
  password: z.string().min(1, "Password is required"),
  csrf: z.string().min(1, "CSRF token is required"),
});

type LoginFormValues = z.infer<typeof loginSchema>;

interface LoginFormProps {
  csrfToken: string;
}

export function LoginForm({ csrfToken }: LoginFormProps) {
  const [state, formAction, isPending] = useActionState<LoginFormState, FormData>(
    login,
    {}
  );

  const { register, handleSubmit, formState: { errors } } = useForm<LoginFormValues>({
    resolver: zodResolver(loginSchema),
    defaultValues: {
      password: "",
      csrf: csrfToken,
    },
  });

  function onSubmit(_data: LoginFormValues, e?: React.BaseSyntheticEvent) {
    e?.preventDefault();
    const form = e?.target as HTMLFormElement;
    const formData = new FormData(form);
    formAction(formData);
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} noValidate className="space-y-4">
      <input type="hidden" {...register("csrf")} value={csrfToken} />

      <div className="space-y-2">
        <Label htmlFor="password">Password</Label>
        <Input
          id="password"
          type="password"
          autoComplete="current-password"
          placeholder="Operator password"
          aria-describedby={
            errors.password ?? state.error ? "password-error" : undefined
          }
          {...register("password")}
        />
        {(errors.password !== undefined || state.error !== undefined) && (
          <p id="password-error" className="text-sm text-destructive" role="alert">
            {errors.password?.message ?? state.error}
          </p>
        )}
      </div>

      <Button type="submit" className="w-full" disabled={isPending}>
        {isPending ? "Signing in..." : "Sign in"}
      </Button>
    </form>
  );
}
