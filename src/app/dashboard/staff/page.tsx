import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { getSession } from "@/lib/session";
import { FileQuestion, UserCheck, ShieldCheck } from "lucide-react";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";

export default async function StaffDashboard() {
  const session = await getSession();

  const recentVerifications = [
    { id: "CUST-001", customer: "John Customer", status: "Approved", timestamp: "5 minutes ago", risk: "low" },
    { id: "CUST-002", customer: "Emily Davis", status: "Manual Review", timestamp: "20 minutes ago", risk: "medium" },
    { id: "CUST-003", customer: "Michael Brown", status: "Approved", timestamp: "1 hour ago", risk: "low" },
    { id: "CUST-004", customer: "Sarah Wilson", status: "Denied", timestamp: "2 hours ago", risk: "high" },
  ];

  return (
    <div className="container mx-auto">
      <h1 className="text-3xl font-bold font-headline mb-6">Staff Dashboard</h1>
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3 mb-6">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Verification Queue</CardTitle>
            <FileQuestion className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">12</div>
            <p className="text-xs text-muted-foreground">Cases requiring manual review</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Customers Verified Today</CardTitle>
            <UserCheck className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">+152</div>
            <p className="text-xs text-muted-foreground">Increase of 5% from yesterday</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Compliance Status</CardTitle>
            <ShieldCheck className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-500">Compliant</div>
            <p className="text-xs text-muted-foreground">All checks passed for today</p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Recent Customer Verifications</CardTitle>
          <CardDescription>A log of recent identity verification activities.</CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Customer ID</TableHead>
                <TableHead>Customer Name</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Risk Level</TableHead>
                <TableHead className="text-right">Timestamp</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {recentVerifications.map((item) => (
                <TableRow key={item.id}>
                  <TableCell className="font-mono text-xs">{item.id}</TableCell>
                  <TableCell className="font-medium">{item.customer}</TableCell>
                  <TableCell>
                    <Badge variant={item.status === 'Denied' ? 'destructive' : item.status === 'Approved' ? 'default' : 'secondary'} className="capitalize">{item.status}</Badge>
                  </TableCell>
                  <TableCell>
                    <Badge variant={item.risk === 'high' ? 'destructive' : item.risk === 'medium' ? 'outline' : 'secondary'} className="capitalize">{item.risk}</Badge>
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
