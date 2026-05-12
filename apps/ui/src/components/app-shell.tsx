// Authenticated app shell — top bar with nav + sign-out form.
// Server component; renders for every authenticated route.

import Link from "next/link";
import { Button } from "@/components/ui/button";

const NAV_ITEMS = [
  { href: "/", label: "Dashboard" },
  { href: "/campaigns", label: "Campaigns" },
  { href: "/vulnerabilities", label: "Vulnerabilities" },
  { href: "/patches", label: "Patches" },
] as const;

export function AppShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-background">
      <header className="border-b">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
          <div className="flex items-center gap-8">
            <div>
              <h1 className="text-lg font-semibold">Security Buddy</h1>
              <p className="text-xs text-muted-foreground">
                Adversarial evaluation
              </p>
            </div>
            <nav className="flex items-center gap-1 text-sm">
              {NAV_ITEMS.map((item) => (
                <Link
                  key={item.href}
                  href={item.href}
                  className="rounded px-3 py-1.5 text-muted-foreground transition hover:bg-muted hover:text-foreground"
                >
                  {item.label}
                </Link>
              ))}
            </nav>
          </div>
          <form action="/logout" method="POST">
            <Button variant="outline" size="sm" type="submit">
              Sign out
            </Button>
          </form>
        </div>
      </header>
      <main className="mx-auto max-w-7xl px-6 py-8">{children}</main>
    </div>
  );
}
