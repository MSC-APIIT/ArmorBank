import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { getSession } from "@/lib/session";
import { Smartphone, ShieldCheck, Clock, MapPin } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { PasskeyPromptHost } from "./passkey-prompt-host";
import Link from "next/link";

export default async function CustomerDashboard() {
  const session = await getSession();

  const recentLogins = [
    {
      id: 1,
      device: "Chrome on macOS",
      location: "New York, NY",
      time: "Now",
      status: "Success",
    },
    {
      id: 2,
      device: "Mobile App on iOS",
      location: "New York, NY",
      time: "2 hours ago",
      status: "Success",
    },
    {
      id: 3,
      device: "Firefox on Windows",
      location: "Brooklyn, NY",
      time: "1 day ago",
      status: "Success (MFA)",
    },
    {
      id: 4,
      device: "Unknown Browser",
      location: "Chicago, IL",
      time: "2 days ago",
      status: "Failed Attempt",
    },
  ];

  return (
    <div className="container mx-auto">
      <h1 className="text-3xl font-bold font-headline mb-6">
        Customer Dashboard
      </h1>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <>
            <PasskeyPromptHost
              shouldPrompt={!!session?.shouldPromptPasskey}
              userId={session?.user?.id}
            />
          </>
          <Card>
            <CardHeader>
              <CardTitle>Recent Login Activity</CardTitle>
              <CardDescription>
                Here is a list of recent sign-ins to your account. If you don't
                recognize an activity, please secure your account immediately.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Device</TableHead>
                    <TableHead>Location</TableHead>
                    <TableHead>Time</TableHead>
                    <TableHead className="text-right">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {recentLogins.map((login) => (
                    <TableRow key={login.id}>
                      <TableCell className="font-medium flex items-center gap-2">
                        <Smartphone size={16} /> {login.device}
                      </TableCell>
                      <TableCell>
                        <MapPin size={16} className="inline-block mr-1" />{" "}
                        {login.location}
                      </TableCell>
                      <TableCell>
                        <Clock size={16} className="inline-block mr-1" />{" "}
                        {login.time}
                      </TableCell>
                      <TableCell className="text-right">
                        <Badge
                          variant={
                            login.status.includes("Failed")
                              ? "destructive"
                              : "default"
                          }
                        >
                          {login.status}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </div>
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <div className="flex items-center gap-4">
                <div className="bg-green-100 dark:bg-green-900/50 p-3 rounded-full">
                  <ShieldCheck className="w-6 h-6 text-green-600 dark:text-green-400" />
                </div>
                <div>
                  <CardTitle>Account Secured</CardTitle>
                  <CardDescription>
                    Your account is protected with Multi-Factor Authentication.
                  </CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <Button className="w-full">Manage Security Settings</Button>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Authenticator App</CardTitle>
              <CardDescription>
                Your primary MFA method is configured.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-between p-3 bg-secondary rounded-lg">
                <div className="flex items-center gap-3">
                  <Smartphone className="h-4 w-4" />
                  <span className="font-medium">Primary Authenticator</span>
                </div>

                <Link href="/dashboard/customer/security">
                  <Button variant="outline" size="sm">
                    Manage
                  </Button>
                </Link>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
