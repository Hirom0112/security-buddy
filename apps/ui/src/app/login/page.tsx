import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import crypto from "crypto";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { LoginForm } from "@/components/login-form";
import { getSession } from "@/lib/auth/session";

export default async function LoginPage() {
  // If already authenticated, redirect to dashboard
  const session = await getSession();
  if (session !== null) {
    redirect("/");
  }

  // Generate a CSRF token and set it as a cookie
  const csrfToken = crypto.randomBytes(32).toString("hex");
  const cookieStore = await cookies();
  cookieStore.set("sb_csrf", csrfToken, {
    httpOnly: true,
    secure: process.env["NODE_ENV"] === "production",
    sameSite: "strict",
    path: "/login",
    maxAge: 60 * 10, // 10 minutes — enough time to fill in the form
  });

  return (
    <main className="flex min-h-screen items-center justify-center bg-background px-4">
      <div className="w-full max-w-sm">
        <div className="mb-8 text-center">
          <h1 className="text-2xl font-bold tracking-tight">Security Buddy</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Adversarial evaluation platform
          </p>
        </div>

        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Operator sign-in</CardTitle>
            <CardDescription>
              Access is restricted to the platform operator.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <LoginForm csrfToken={csrfToken} />
          </CardContent>
        </Card>
      </div>
    </main>
  );
}
