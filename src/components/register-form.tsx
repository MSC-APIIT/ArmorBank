"use client";

import React, { useActionState } from "react";
import { useFormStatus } from "react-dom";
import { register, type RegisterState } from "@/lib/actions";
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
import Link from "next/link";

function SubmitButton() {
  const { pending } = useFormStatus();
  return (
    <Button type="submit" className="w-full" disabled={pending}>
      {pending ? "Creating..." : "Create account"}
    </Button>
  );
}

export function RegisterForm() {
  const initialState: RegisterState = {};
  const [state, dispatch] = useActionState(register, initialState);

  return (
    <Card className="w-full max-w-sm">
      <form action={dispatch}>
        <CardHeader className="text-center">
          <CardTitle className="text-2xl font-headline">
            Create Account
          </CardTitle>
          <CardDescription>Register to access your account.</CardDescription>
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
            <Label htmlFor="password">Password</Label>
            <Input id="password" name="password" type="password" required />
          </div>

          <div className="space-y-2">
            <Label htmlFor="confirmPassword">Confirm Password</Label>
            <Input
              id="confirmPassword"
              name="confirmPassword"
              type="password"
              required
            />
          </div>

          {state?.error && (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertTitle>Register Failed</AlertTitle>
              <AlertDescription>{state.error}</AlertDescription>
            </Alert>
          )}
        </CardContent>

        <CardFooter className="flex flex-col gap-3">
          <SubmitButton />
          <Link
            href="/login"
            className="text-sm text-foreground/70 hover:text-foreground"
          >
            Already have an account? Sign in
          </Link>
        </CardFooter>
      </form>
    </Card>
  );
}
