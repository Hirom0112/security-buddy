import { cookies } from "next/headers";
import { redirect } from "next/navigation";
/**
 * POST /logout — clears the session cookie and redirects to /login.
 * GET is explicitly rejected so logout cannot be triggered by link prefetch.
 */
export async function POST(): Promise<never> {
  const cookieStore = await cookies();
  cookieStore.delete("sb_session");
  redirect("/login");
}
