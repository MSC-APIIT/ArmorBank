import { UserNav } from "@/components/user-nav";
import { getSession } from "@/lib/session";
import { ShieldCheck } from "lucide-react";
import Link from "next/link";
import { redirect } from "next/navigation";

export default async function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const session = await getSession();

  if (!session) {
    redirect('/login');
  }

  return (
    <div className="flex flex-col min-h-screen">
      <header className="sticky top-0 z-50 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container flex h-14 items-center">
          <Link href={`/dashboard/${session.user.role}`} className="mr-6 flex items-center space-x-2">
            <ShieldCheck className="h-6 w-6 text-primary" />
            <span className="font-bold font-headline">BankAuth</span>
          </Link>
          <div className="flex-1" />
          <UserNav user={session.user} />
        </div>
      </header>
      <main className="flex-1 p-4 md:p-8">
        {children}
      </main>
    </div>
  );
}
