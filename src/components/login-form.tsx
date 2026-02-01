"use client";

import React, { useActionState, useEffect } from "react";
import { useFormStatus } from "react-dom";
import { useRouter } from "next/navigation";
import { login, type LoginState } from "@/lib/actions";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { AlertCircle } from "lucide-react";

function SubmitButton() {
  const { pending } = useFormStatus();
  return (
    <Button type="submit" className="w-full" disabled={pending}>
      {pending ? "Signing In..." : "Sign In"}
    </Button>
  );
}

export function LoginForm() {
  const router = useRouter();
  const initialState: LoginState = { status: "idle" };

  const [state, dispatch] = useActionState<LoginState, FormData>(
    login,
    initialState,
  );

  useEffect(() => {
    if (state.status === "mfa") {
      router.replace(
        `/mfa?token=${encodeURIComponent(state.mfaToken)}&risk=${state.riskScore}&preferred=${state.preferredMfa}`,
      );
      router.refresh();
    }
    if (state.status === "success") {
      router.replace(state.redirectTo);
      router.refresh();
    }
  }, [state, router]);

  return (
    <Card className="w-full max-w-sm">
      <form action={dispatch}>
        <CardHeader className="text-center">
          <CardTitle className="text-2xl font-headline">Sign In</CardTitle>
          <CardDescription>
            Enter your credentials to access your account.
          </CardDescription>
        </CardHeader>

        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="email">Email</Label>
            <Input
              id="email"
              name="email"
              type="email"
              placeholder="m@example.com"
              required
            />
          </div>

          <div className="space-y-2">
            <div className="flex items-center">
              <Label htmlFor="password">Password</Label>
            </div>
            <Input id="password" name="password" type="password" required />
          </div>

          {state.status === "error" && (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertTitle>Login Failed</AlertTitle>
              <AlertDescription>{state.error}</AlertDescription>
            </Alert>
          )}
        </CardContent>

        <CardFooter className="flex flex-col gap-4">
          <SubmitButton />
          <div className="text-sm text-center text-muted-foreground">
            Don’t have an account?{" "}
            <button
              type="button"
              onClick={() => router.push("/register")}
              className="font-medium text-primary hover:underline"
            >
              Create one
            </button>
          </div>
        </CardFooter>
      </form>
    </Card>
  );
}
