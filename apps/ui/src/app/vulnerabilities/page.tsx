import { redirect } from "next/navigation";
import Link from "next/link";
import { getSession } from "@/lib/auth/session";
import { AppShell } from "@/components/app-shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SeverityBadge, VulnStatusBadge } from "@/components/badges";
import { listVulnerabilities } from "@/lib/db/queries";

export const dynamic = "force-dynamic";

export default async function VulnerabilitiesPage() {
  const session = await getSession();
  if (session === null) redirect("/login");

  let vulns;
  try {
    vulns = await listVulnerabilities();
  } catch (err) {
    return (
      <AppShell>
        <DbError error={err} />
      </AppShell>
    );
  }

  const drafts = vulns.filter((v) => v.status === "draft");
  const rest = vulns.filter((v) => v.status !== "draft");

  return (
    <AppShell>
      <div className="space-y-6">
        {drafts.length > 0 && (
          <Card className="border-amber-300">
            <CardHeader>
              <CardTitle className="text-base">
                Awaiting your decision ({drafts.length})
              </CardTitle>
              <p className="text-xs text-muted-foreground">
                Critical-severity findings stay in <code>draft</code> until the
                operator confirms. Confirming opens the Patch Agent workflow.
              </p>
            </CardHeader>
            <CardContent>
              <VulnTable rows={drafts} />
            </CardContent>
          </Card>
        )}

        <Card>
          <CardHeader>
            <CardTitle>All vulnerabilities</CardTitle>
          </CardHeader>
          <CardContent>
            {rest.length === 0 && drafts.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                No vulnerabilities recorded yet.
              </p>
            ) : (
              <VulnTable rows={rest} />
            )}
          </CardContent>
        </Card>
      </div>
    </AppShell>
  );
}

function VulnTable({
  rows,
}: {
  rows: Awaited<ReturnType<typeof listVulnerabilities>>;
}) {
  if (rows.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">No matching findings.</p>
    );
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b text-left text-xs text-muted-foreground">
            <th className="py-2 pr-4">ID</th>
            <th className="py-2 pr-4">Title</th>
            <th className="py-2 pr-4">Severity</th>
            <th className="py-2 pr-4">Status</th>
            <th className="py-2 pr-4">OWASP</th>
            <th className="py-2">Reported</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((v) => (
            <tr key={v.id} className="border-b last:border-0">
              <td className="py-2 pr-4 font-mono text-xs">
                <Link
                  href={`/vulnerabilities/${v.id}`}
                  className="text-blue-700 hover:underline"
                >
                  {v.vuln_id}
                </Link>
              </td>
              <td className="py-2 pr-4 max-w-md truncate">{v.title}</td>
              <td className="py-2 pr-4">
                <SeverityBadge severity={v.severity} />
              </td>
              <td className="py-2 pr-4">
                <VulnStatusBadge status={v.status} />
              </td>
              <td className="py-2 pr-4 text-xs">{v.owasp_llm_id}</td>
              <td className="py-2 text-xs text-muted-foreground">
                {new Date(v.created_at).toLocaleString()}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function DbError({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : String(error);
  return (
    <div className="rounded-lg border border-dashed border-amber-400 bg-amber-50 px-6 py-4 text-sm text-amber-900">
      <p className="font-medium">Database unreachable</p>
      <p className="mt-1 text-xs">{message}</p>
    </div>
  );
}
