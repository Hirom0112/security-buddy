import { notFound, redirect } from "next/navigation";
import { getSession } from "@/lib/auth/session";
import { AppShell } from "@/components/app-shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { CampaignStatusBadge, VerdictBadge } from "@/components/badges";
import {
  getCampaign,
  listAttacksForCampaign,
  listVerdictsForAttacks,
} from "@/lib/db/queries";

export const dynamic = "force-dynamic";

interface PageProps {
  params: Promise<{ id: string }>;
}

export default async function CampaignDetailPage({ params }: PageProps) {
  const session = await getSession();
  if (session === null) redirect("/login");

  const { id } = await params;
  const campaign = await getCampaign(id);
  if (campaign === null) notFound();

  const attacks = await listAttacksForCampaign(id);
  const verdicts = await listVerdictsForAttacks(attacks.map((a) => a.id));

  return (
    <AppShell>
      <div className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <span>
                Campaign{" "}
                <code className="text-sm font-normal text-muted-foreground">
                  {id.slice(0, 8)}
                </code>
              </span>
              <CampaignStatusBadge status={campaign.status} />
            </CardTitle>
          </CardHeader>
          <CardContent className="grid gap-4 sm:grid-cols-4 text-sm">
            <div>
              <p className="text-xs text-muted-foreground">Subcategory</p>
              <p className="font-medium">
                {campaign.target_subcategory ?? "—"}
              </p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Budget</p>
              <p className="tabular-nums">
                ${Number(campaign.budget_usd).toFixed(2)}
              </p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Spent</p>
              <p className="tabular-nums">
                ${Number(campaign.spent_usd).toFixed(2)}
              </p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Created</p>
              <p>{new Date(campaign.created_at).toLocaleString()}</p>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">
              Attacks ({attacks.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            {attacks.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                No attacks fired yet.
              </p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b text-left text-xs text-muted-foreground">
                      <th className="py-2 pr-4">Mutation</th>
                      <th className="py-2 pr-4">Status</th>
                      <th className="py-2 pr-4">HTTP</th>
                      <th className="py-2 pr-4">Verdict</th>
                      <th className="py-2">Input (truncated)</th>
                    </tr>
                  </thead>
                  <tbody>
                    {attacks.map((a) => {
                      const v = verdicts.get(a.id);
                      return (
                        <tr key={a.id} className="border-b last:border-0">
                          <td className="py-2 pr-4 text-xs">
                            {a.mutation_strategy}
                          </td>
                          <td className="py-2 pr-4 text-xs text-muted-foreground">
                            {a.status.replace(/_/g, " ")}
                          </td>
                          <td className="py-2 pr-4 tabular-nums text-xs">
                            {a.target_response_status ?? "—"}
                          </td>
                          <td className="py-2 pr-4">
                            {v ? <VerdictBadge verdict={v.verdict} /> : "—"}
                          </td>
                          <td className="py-2 max-w-md truncate text-xs text-muted-foreground">
                            {a.attack_input}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </AppShell>
  );
}
