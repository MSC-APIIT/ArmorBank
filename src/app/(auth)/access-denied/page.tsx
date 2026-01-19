import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { getSession } from "@/lib/session";
import { ShieldAlert } from "lucide-react";
import Link from "next/link";
import { redirect } from "next/navigation";

export default async function AccessDeniedPage() {
    const session = await getSession();
    
    if (!session) {
        redirect('/login');
    }

    // Don't allow users on this page if they aren't in a denied state
    // This can happen if they navigate here directly.
    const headers = require('next/headers');
    const referer = headers().get('referer');
    const onDeniedPath = referer ? new URL(referer).pathname.startsWith('/dashboard') : false;

    if (session && !session.isMfaPending && !onDeniedPath) {
        redirect(`/dashboard/${session.user.role}`);
    }


    const dashboardUrl = `/dashboard/${session.user.role}`;

    return (
        <div className="flex min-h-screen items-center justify-center bg-secondary">
            <Card className="w-full max-w-md text-center">
                <CardHeader>
                    <div className="mx-auto bg-destructive/20 rounded-full p-4 w-fit">
                        <ShieldAlert className="w-12 h-12 text-destructive" />
                    </div>
                    <CardTitle className="mt-4 text-2xl font-headline">Access Denied</CardTitle>
                    <CardDescription>You do not have permission to view this page.</CardDescription>
                </CardHeader>
                <CardContent>
                    <p className="text-muted-foreground">
                        Your current role of "{session.user.role}" does not grant access to this resource.
                        If you believe this is an error, please contact your system administrator.
                    </p>
                    <Button asChild className="mt-6">
                        <Link href={dashboardUrl}>Return to My Dashboard</Link>
                    </Button>
                </CardContent>
            </Card>
        </div>
    );
}
