import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { getSession } from "@/lib/session";
import { Users, Clock, ShieldAlert, Activity } from "lucide-react";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";

export default async function AdminDashboard() {
  const session = await getSession();

  const recentActions = [
    { id: 1, user: "Super Admin", action: "Granted 'staff' role to jane.staff@example.com", timestamp: "2 minutes ago", level: "info" },
    { id: 2, user: "Super Admin", action: "Reset password for customer@example.com", timestamp: "1 hour ago", level: "warning" },
    { id: 3, user: "System", action: "Security policy 'MFA-On-Risk' updated automatically", timestamp: "3 hours ago", level: "info" },
    { id: 4, user: "Super Admin", action: "Viewed high-risk login attempts", timestamp: "5 hours ago", level: "info" },
    { id: 5, user: "System", action: "High-risk login attempt blocked from IP 123.45.67.89", timestamp: "1 day ago", level: "critical" },
  ];

  return (
    <div className="container mx-auto">
      <h1 className="text-3xl font-bold font-headline mb-6">Administrator Dashboard</h1>
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4 mb-6">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Users</CardTitle>
            <Users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">1,234</div>
            <p className="text-xs text-muted-foreground">+20.1% from last month</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Sessions</CardTitle>
            <Clock className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">+73</div>
            <p className="text-xs text-muted-foreground">Currently logged in</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Security Alerts</CardTitle>
            <ShieldAlert className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-destructive">5</div>
            <p className="text-xs text-muted-foreground">High-risk events in 24h</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">System Health</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-500">Normal</div>
            <p className="text-xs text-muted-foreground">All systems operational</p>
          </CardContent>
        </Card>
      </div>
      
      <Card>
        <CardHeader>
          <CardTitle>Recent Administrative Actions</CardTitle>
          <CardDescription>An audit log of recent privileged activities on the platform.</CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>User</TableHead>
                <TableHead>Action</TableHead>
                <TableHead className="text-right">Timestamp</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {recentActions.map((item) => (
                <TableRow key={item.id}>
                  <TableCell className="font-medium">{item.user}</TableCell>
                  <TableCell>
                     <Badge variant={item.level === 'critical' ? 'destructive' : 'secondary'} className="mr-2 capitalize">{item.level}</Badge>
                    {item.action}
                  </TableCell>
                  <TableCell className="text-right text-muted-foreground">{item.timestamp}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
