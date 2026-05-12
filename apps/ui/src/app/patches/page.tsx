import { redirect } from "next/navigation";
import Link from "next/link";
import { getSession } from "@/lib/auth/session";
import { AppShell } from "@/components/app-shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { PatchStatusBadge } from "@/components/badges";
import { listPatches } from "@/lib/db/queries";
import { reviewPatchAction } from "./actions";

export const dynamic = "force-dynamic";

export default async function PatchesPage() {
  const session = await getSession();
  if (session === null) redirect("/login");

  let patches;
  try {
    patches = await listPatches();
  } catch (err) {
    return (
      <AppShell>
        <DbError error={err} />
      </AppShell>
    );
  }

  const pending = patches.filter((p) => p.status === "awaiting_human_review");
  const resolved = patches.filter((p) => p.status !== "awaiting_human_review");

  return (
    <AppShell>
      <div className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle>Pending review ({pending.length})</CardTitle>
            <p className="text-xs text-muted-foreground">
              Merge happens on GitHub. The buttons below mark the patch row in
              Postgres after you act on the PR. Merging the PR on GitHub also
              flips this row via the webhook.
            </p>
          </CardHeader>
          <CardContent>
            {pending.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                No patches awaiting review.
              </p>
            ) : (
              <ul className="space-y-3">
                {pending.map((p) => (
                  <li
                    key={p.id}
                    className="flex flex-col gap-2 rounded border p-3 sm:flex-row sm:items-center sm:justify-between"
                  >
                    <div className="space-y-1 text-sm">
                      <div className="flex items-center gap-2">
                        <a
                          href={p.pr_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="font-medium text-blue-700 hover:underline"
                        >
                          {p.branch_name}
                        </a>
                        <PatchStatusBadge status={p.status} />
                      </div>
                      {p.vuln_id !== null && (
                        <Link
                          href={`/vulnerabilities/${p.vulnerability_id}`}
                          className="text-xs text-muted-foreground hover:underline"
                        >
                          {p.vuln_id}
                        </Link>
                      )}
                      <p className="text-xs text-muted-foreground">
                        Opened {new Date(p.created_at).toLocaleString()}
                      </p>
                    </div>
                    <div className="flex gap-2">
                      <form action={reviewPatchAction}>
                        <input type="hidden" name="id" value={p.id} />
                        <input type="hidden" name="decision" value="merged" />
                        <Button type="submit" size="sm">
                          Mark merged
                        </Button>
                      </form>
                      <form action={reviewPatchAction}>
                        <input type="hidden" name="id" value={p.id} />
                        <input type="hidden" name="decision" value="rejected" />
                        <Button type="submit" size="sm" variant="outline">
                          Reject
                        </Button>
                      </form>
                      <form action={reviewPatchAction}>
                        <input type="hidden" name="id" value={p.id} />
                        <input type="hidden" name="decision" value="ci_failed" />
                        <Button type="submit" size="sm" variant="outline">
                          CI failed
                        </Button>
                      </form>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">
              Closed ({resolved.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            {resolved.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                No closed patches yet.
              </p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b text-left text-xs text-muted-foreground">
                      <th className="py-2 pr-4">Branch</th>
                      <th className="py-2 pr-4">Vuln</th>
                      <th className="py-2 pr-4">Status</th>
                      <th className="py-2 pr-4">Opened</th>
                      <th className="py-2">Merged</th>
                    </tr>
                  </thead>
                  <tbody>
                    {resolved.map((p) => (
                      <tr key={p.id} className="border-b last:border-0">
                        <td className="py-2 pr-4">
                          <a
                            href={p.pr_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-blue-700 hover:underline"
                          >
                            {p.branch_name}
                          </a>
                        </td>
                        <td className="py-2 pr-4 text-xs">
                          {p.vuln_id ?? "—"}
                        </td>
                        <td className="py-2 pr-4">
                          <PatchStatusBadge status={p.status} />
                        </td>
                        <td className="py-2 pr-4 text-xs text-muted-foreground">
                          {new Date(p.created_at).toLocaleString()}
                        </td>
                        <td className="py-2 text-xs text-muted-foreground">
                          {p.merged_at
                            ? new Date(p.merged_at).toLocaleString()
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
      </div>
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
