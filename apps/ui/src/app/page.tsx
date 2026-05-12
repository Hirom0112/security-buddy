import { redirect } from "next/navigation";
import Link from "next/link";
import { Suspense } from "react";
import { getSession } from "@/lib/auth/session";
import { AppShell } from "@/components/app-shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SeverityBadge } from "@/components/badges";
import { coverageSnapshot, dashboardSummary } from "@/lib/db/queries";

export const dynamic = "force-dynamic";

export default async function DashboardPage() {
  const session = await getSession();
  if (session === null) redirect("/login");

  return (
    <AppShell>
      <div className="space-y-8">
        <Suspense fallback={<DashboardSkeleton />}>
          <DashboardContent />
        </Suspense>
      </div>
    </AppShell>
  );
}

async function DashboardContent() {
  let summary;
  let coverage;
  try {
    [summary, coverage] = await Promise.all([
      dashboardSummary(),
      coverageSnapshot(),
    ]);
  } catch (err) {
    return <DbErrorBanner error={err} />;
  }

  const coveragePct =
    summary.total_subcategories === 0
      ? 0
      : Math.round(
          (summary.covered_subcategories / summary.total_subcategories) * 100
        );

  return (
    <>
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Coverage</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold">
              {summary.covered_subcategories} / {summary.total_subcategories}
            </p>
            <p className="mt-1 text-xs text-muted-foreground">
              Subcategories touched ({coveragePct}%)
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">
              Open vulnerabilities
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold">
              {Object.values(summary.open_vulnerabilities_by_severity).reduce(
                (a, b) => a + b,
                0
              )}
            </p>
            <div className="mt-2 flex flex-wrap gap-1">
              {(["critical", "high", "medium", "low"] as const).map((sev) =>
                summary.open_vulnerabilities_by_severity[sev] > 0 ? (
                  <span key={sev} className="flex items-center gap-1 text-xs">
                    <SeverityBadge severity={sev} />
                    <span className="font-medium">
                      {summary.open_vulnerabilities_by_severity[sev]}
                    </span>
                  </span>
                ) : null
              )}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Pending PRs</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold">{summary.pending_patches}</p>
            <Link
              href="/patches"
              className="mt-1 text-xs text-blue-700 hover:underline"
            >
              View queue →
            </Link>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Cost</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold">
              {formatUsd(summary.total_cost_usd)}
            </p>
            <p className="mt-1 text-xs text-muted-foreground">
              {formatUsd(summary.last_24h_cost_usd)} in last 24h
            </p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Coverage map</CardTitle>
        </CardHeader>
        <CardContent>
          {coverage.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No attacks fired yet.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left text-xs text-muted-foreground">
                    <th className="py-2 pr-4">Category / Subcategory</th>
                    <th className="py-2 pr-4">Attempts</th>
                    <th className="py-2 pr-4">Exploits</th>
                    <th className="py-2 pr-4">Partials</th>
                    <th className="py-2">Last attempted</th>
                  </tr>
                </thead>
                <tbody>
                  {coverage.map((row) => (
                    <tr
                      key={`${row.category}/${row.subcategory}`}
                      className="border-b last:border-0"
                    >
                      <td className="py-2 pr-4">
                        <span className="text-muted-foreground">
                          {row.category}
                        </span>
                        <span className="px-1">/</span>
                        <span className="font-medium">{row.subcategory}</span>
                      </td>
                      <td className="py-2 pr-4 tabular-nums">
                        {row.attempts}
                      </td>
                      <td className="py-2 pr-4 tabular-nums text-red-700">
                        {row.exploits}
                      </td>
                      <td className="py-2 pr-4 tabular-nums text-orange-700">
                        {row.partials}
                      </td>
                      <td className="py-2 text-xs text-muted-foreground">
                        {row.last_attempted_at
                          ? new Date(row.last_attempted_at).toLocaleString()
                          : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </>
  );
}

function DashboardSkeleton() {
  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
      {[1, 2, 3, 4].map((i) => (
        <Card key={i}>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Loading…</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-8 w-16 animate-pulse rounded bg-muted" />
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

function DbErrorBanner({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : String(error);
  return (
    <div className="rounded-lg border border-dashed border-amber-400 bg-amber-50 px-6 py-4 text-sm text-amber-900">
      <p className="font-medium">Database unreachable</p>
      <p className="mt-1 text-xs">{message}</p>
      <p className="mt-2 text-xs">
        Set <code className="rounded bg-amber-100 px-1">DATABASE_URL</code> and
        ensure Postgres is reachable from the UI process.
      </p>
    </div>
  );
}

function formatUsd(raw: string): string {
  const n = Number(raw);
  if (!Number.isFinite(n)) return "$0.00";
  return n.toLocaleString("en-US", {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: 2,
  });
}
