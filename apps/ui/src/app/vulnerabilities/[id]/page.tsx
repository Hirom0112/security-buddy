import { notFound, redirect } from "next/navigation";
import { getSession } from "@/lib/auth/session";
import { AppShell } from "@/components/app-shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { SeverityBadge, VulnStatusBadge } from "@/components/badges";
import {
  getVulnerability,
  listPatchesForVulnerability,
} from "@/lib/db/queries";
import {
  confirmVulnerability,
  dismissVulnerability,
} from "./actions";

export const dynamic = "force-dynamic";

interface PageProps {
  params: Promise<{ id: string }>;
}

export default async function VulnerabilityDetailPage({ params }: PageProps) {
  const session = await getSession();
  if (session === null) redirect("/login");

  const { id } = await params;
  const vuln = await getVulnerability(id);
  if (vuln === null) notFound();

  const patches = await listPatchesForVulnerability(id);

  return (
    <AppShell>
      <div className="space-y-6">
        <Card>
          <CardHeader>
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="text-xs text-muted-foreground">{vuln.vuln_id}</p>
                <CardTitle className="mt-1 text-xl leading-tight">
                  {vuln.title}
                </CardTitle>
                <div className="mt-2 flex flex-wrap items-center gap-2 text-xs">
                  <SeverityBadge severity={vuln.severity} />
                  <VulnStatusBadge status={vuln.status} />
                  <span className="text-muted-foreground">
                    {new Date(vuln.created_at).toLocaleString()}
                  </span>
                </div>
              </div>
            </div>
          </CardHeader>
          <CardContent className="grid gap-4 sm:grid-cols-3 text-xs">
            <div>
              <p className="text-muted-foreground">OWASP LLM</p>
              <p className="font-medium">{vuln.owasp_llm_id}</p>
            </div>
            <div>
              <p className="text-muted-foreground">MITRE ATLAS</p>
              <p className="font-medium">{vuln.mitre_atlas_technique_id}</p>
            </div>
            <div>
              <p className="text-muted-foreground">HIPAA</p>
              <p className="font-medium">{vuln.hipaa_safeguard}</p>
            </div>
          </CardContent>
        </Card>

        {vuln.status === "draft" && (
          <Card className="border-amber-300 bg-amber-50/40">
            <CardHeader>
              <CardTitle className="text-base">
                Operator decision required
              </CardTitle>
              <p className="text-xs text-muted-foreground">
                Critical-severity finding. Confirming flips this to{" "}
                <code>open</code> and queues the Patch Agent. Dismissing
                acknowledges the alert and leaves status unchanged.
              </p>
            </CardHeader>
            <CardContent>
              <div className="flex gap-3">
                <form action={confirmVulnerability}>
                  <input type="hidden" name="id" value={vuln.id} />
                  <Button type="submit">Confirm finding</Button>
                </form>
                <form action={dismissVulnerability}>
                  <input type="hidden" name="id" value={vuln.id} />
                  <Button type="submit" variant="outline">
                    Dismiss
                  </Button>
                </form>
              </div>
            </CardContent>
          </Card>
        )}

        <Section title="Clinical impact" body={vuln.clinical_impact} />
        <Section title="Reproduction steps" body={vuln.reproduction_steps} />
        <Section title="Observed behavior" body={vuln.observed_behavior} />
        <Section title="Expected behavior" body={vuln.expected_behavior} />
        <Section
          title="Recommended remediation"
          body={vuln.recommended_remediation}
        />

        <Card>
          <CardHeader>
            <CardTitle className="text-base">
              Linked patches ({patches.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            {patches.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                No patches opened yet for this vulnerability.
              </p>
            ) : (
              <ul className="space-y-2 text-sm">
                {patches.map((p) => (
                  <li key={p.id} className="flex items-center gap-3">
                    <a
                      href={p.pr_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-700 hover:underline"
                    >
                      {p.branch_name}
                    </a>
                    <span className="text-xs text-muted-foreground">
                      {p.status.replace(/_/g, " ")}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>
    </AppShell>
  );
}

function Section({ title, body }: { title: string; body: string }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{title}</CardTitle>
      </CardHeader>
      <CardContent>
        <p className="whitespace-pre-wrap text-sm leading-relaxed">{body}</p>
      </CardContent>
    </Card>
  );
}
