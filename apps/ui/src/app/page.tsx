import { redirect } from "next/navigation";
import { getSession } from "@/lib/auth/session";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";

export default async function DashboardPage() {
  // Defense in depth: middleware handles the primary redirect, but we also
  // check here in case middleware is bypassed or misconfigured.
  const session = await getSession();
  if (session === null) {
    redirect("/login");
  }

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
          <div>
            <h1 className="text-xl font-semibold">Security Buddy</h1>
            <p className="text-xs text-muted-foreground">
              Adversarial evaluation platform
            </p>
          </div>
          <form action="/logout" method="POST">
            <Button variant="outline" size="sm" type="submit">
              Sign out
            </Button>
          </form>
        </div>
      </header>

      {/* Main content */}
      <main className="mx-auto max-w-7xl px-6 py-8">
        {/* Empty state banner */}
        <div className="mb-8 rounded-lg border border-dashed bg-muted/30 px-6 py-4">
          <p className="text-sm text-muted-foreground">
            No campaigns yet — backend connection pending Slice 1.
          </p>
        </div>

        {/* Dashboard grid */}
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {/* Coverage map */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Coverage map</CardTitle>
              <CardDescription>Attack subcategories tested</CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-2xl font-bold">0 / 13</p>
              <p className="mt-1 text-xs text-muted-foreground">
                Subcategories with coverage
              </p>
            </CardContent>
          </Card>

          {/* Open vulnerabilities */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">
                Open vulnerabilities
              </CardTitle>
              <CardDescription>Confirmed and awaiting fix</CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-2xl font-bold">0</p>
              <p className="mt-1 text-xs text-muted-foreground">
                No confirmed exploits
              </p>
            </CardContent>
          </Card>

          {/* Pending PRs */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Pending PRs</CardTitle>
              <CardDescription>Awaiting operator review</CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-2xl font-bold">0</p>
              <p className="mt-1 text-xs text-muted-foreground">
                No proposed patches
              </p>
            </CardContent>
          </Card>

          {/* Last campaign cost */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">
                Last campaign cost
              </CardTitle>
              <CardDescription>LLM spend for most recent run</CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-2xl font-bold">$0.00</p>
              <p className="mt-1 text-xs text-muted-foreground">
                No campaigns run yet
              </p>
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  );
}
