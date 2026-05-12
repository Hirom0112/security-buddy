import { redirect } from "next/navigation";
import Link from "next/link";
import { getSession } from "@/lib/auth/session";
import { AppShell } from "@/components/app-shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { CampaignStatusBadge } from "@/components/badges";
import { listCampaigns } from "@/lib/db/queries";

export const dynamic = "force-dynamic";

export default async function CampaignsPage() {
  const session = await getSession();
  if (session === null) redirect("/login");

  let campaigns;
  try {
    campaigns = await listCampaigns();
  } catch (err) {
    return (
      <AppShell>
        <DbError error={err} />
      </AppShell>
    );
  }

  return (
    <AppShell>
      <Card>
        <CardHeader>
          <CardTitle>Campaigns</CardTitle>
        </CardHeader>
        <CardContent>
          {campaigns.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No campaigns yet. Run{" "}
              <code className="rounded bg-muted px-1">
                POST /api/v1/campaigns/start
              </code>{" "}
              against the API to kick one off.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left text-xs text-muted-foreground">
                    <th className="py-2 pr-4">Subcategory</th>
                    <th className="py-2 pr-4">Status</th>
                    <th className="py-2 pr-4">Budget</th>
                    <th className="py-2 pr-4">Spent</th>
                    <th className="py-2 pr-4">Created</th>
                    <th className="py-2" />
                  </tr>
                </thead>
                <tbody>
                  {campaigns.map((c) => (
                    <tr key={c.id} className="border-b last:border-0">
                      <td className="py-2 pr-4 font-medium">
                        {c.target_subcategory ?? "—"}
                      </td>
                      <td className="py-2 pr-4">
                        <CampaignStatusBadge status={c.status} />
                      </td>
                      <td className="py-2 pr-4 tabular-nums">
                        ${Number(c.budget_usd).toFixed(2)}
                      </td>
                      <td className="py-2 pr-4 tabular-nums">
                        ${Number(c.spent_usd).toFixed(2)}
                      </td>
                      <td className="py-2 pr-4 text-xs text-muted-foreground">
                        {new Date(c.created_at).toLocaleString()}
                      </td>
                      <td className="py-2">
                        <Link
                          href={`/campaigns/${c.id}`}
                          className="text-xs text-blue-700 hover:underline"
                        >
                          View →
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </AppShell>
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
