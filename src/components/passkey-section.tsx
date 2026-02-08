"use client";

import React, { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { KeyRound } from "lucide-react";
import { PasskeyPromptHost } from "@/app/dashboard/customer/passkey-prompt-host";

type Props = {
  userId?: string;
  shouldPrompt: boolean;
  hasPasskey: boolean;
};

export default function PasskeySection({
  userId,
  shouldPrompt,
  hasPasskey,
}: Props) {
  const [forceKey, setForceKey] = useState(0);

  // ✅ DB truth from API
  const [dbHasPasskey, setDbHasPasskey] = useState<boolean | null>(null);

  // ✅ Check passkey count after dashboard loads
  useEffect(() => {
    let alive = true;

    (async () => {
      try {
        const res = await fetch("/api/mfa/webauthn/status", {
          cache: "no-store",
        });
        const data = await res.json().catch(() => ({}));

        if (!alive) return;

        if (res.ok) setDbHasPasskey(!!data.hasPasskey);
        else setDbHasPasskey(true); // safer: don't annoy user if status fails
      } catch {
        if (alive) setDbHasPasskey(true);
      }
    })();

    return () => {
      alive = false;
    };
  }, []);

  const effectiveHasPasskey = dbHasPasskey ?? hasPasskey;

  useEffect(() => {
    if (dbHasPasskey === null) return;

    if (dbHasPasskey === true) return;

    if (shouldPrompt) {
      setForceKey((k) => k + 1);
    }
  }, [shouldPrompt, dbHasPasskey]);

  if (!userId) return null;

  return (
    <>
      <PasskeyPromptHost
        shouldPrompt={false}
        userId={userId}
        hasPasskey={effectiveHasPasskey}
        forceOpenKey={forceKey}
      />

      <Card className="mb-6">
        <CardContent className="flex items-center justify-between gap-3 p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-full bg-secondary">
              <KeyRound className="h-4 w-4" />
            </div>

            <div className="space-y-0.5">
              <div className="flex items-center gap-2">
                <span className="font-medium">Passkey (Biometric)</span>

                {dbHasPasskey === null ? (
                  <Badge variant="secondary">Checking...</Badge>
                ) : effectiveHasPasskey ? (
                  <Badge variant="default">Enabled</Badge>
                ) : (
                  <Badge variant="secondary">Not set</Badge>
                )}
              </div>

              <p className="text-sm text-muted-foreground">
                {dbHasPasskey === null
                  ? "Checking passkey status..."
                  : effectiveHasPasskey
                    ? "Your account can use biometric/passkey sign-in."
                    : "Add a passkey to secure your account and speed up login."}
              </p>
            </div>
          </div>

          <Button
            variant={effectiveHasPasskey ? "outline" : "default"}
            onClick={() => setForceKey((k) => k + 1)}
            disabled={dbHasPasskey === null}
          >
            {effectiveHasPasskey ? "Manage" : "Set up"}
          </Button>
        </CardContent>
      </Card>
    </>
  );
}
