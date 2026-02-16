import { MfaForm } from "@/components/mfa-form";
import { getSession } from "@/lib/session";
import { redirect } from "next/navigation";

export default async function MfaPage() {
  const session = await getSession();

  if (session && !session.isMfaPending) {
    redirect(`/dashboard/${session.user.role ?? "customer"}`);
  }

  return <MfaForm />;
}
