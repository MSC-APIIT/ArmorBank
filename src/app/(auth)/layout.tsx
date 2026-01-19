import Link from "next/link";
import { ShieldCheck } from "lucide-react";

export default function AuthLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center p-4 bg-secondary dark:bg-background">
       <div className="absolute top-4 left-4">
        <Link href="/" className="flex items-center space-x-2 text-foreground/80 hover:text-foreground">
          <ShieldCheck className="h-6 w-6 text-primary" />
          <span className="font-bold font-headline">BankAuth</span>
        </Link>
      </div>
      {children}
    </main>
  );
}
