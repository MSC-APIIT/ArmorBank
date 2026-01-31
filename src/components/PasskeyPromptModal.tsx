"use client";

import React from "react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export function PasskeyPromptModal({
  open,
  onSkip,
  onAddPasskey,
  loading,
  status,
}: {
  open: boolean;
  onSkip: () => void;
  onAddPasskey: () => void;
  loading?: boolean;
  status?: string | null;
}) {
  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
      <Card className="w-full max-w-md shadow-xl">
        <CardHeader className="text-center">
          <CardTitle className="text-xl">Add a passkey?</CardTitle>
          <CardDescription>
            Use Face ID / Fingerprint / Windows Hello for faster and safer
            sign-in next time.
          </CardDescription>
        </CardHeader>

        <CardContent className="text-sm text-muted-foreground space-y-2">
          <p>
            This uses your device security. We never see your biometric data.
          </p>
          <p>You can skip and do it later.</p>

          {status ? (
            <div className="mt-3 rounded-md bg-secondary px-3 py-2 text-sm">
              {status}
            </div>
          ) : null}
        </CardContent>

        <CardFooter className="flex gap-2">
          <Button
            variant="secondary"
            className="w-full"
            onClick={onSkip}
            disabled={!!loading}
          >
            Skip for now
          </Button>

          <Button
            className="w-full"
            onClick={onAddPasskey}
            disabled={!!loading}
          >
            {loading ? "Processing..." : "Add passkey"}
          </Button>
        </CardFooter>
      </Card>
    </div>
  );
}
