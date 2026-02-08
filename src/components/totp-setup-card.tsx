"use client";

import React, { useState } from "react";
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
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { AlertCircle, ShieldCheck } from "lucide-react";

type StartResp = {
  ok: boolean;
  enrollmentToken: string;
  qrDataUrl: string;
  manualKey: string;
};

export default function TotpSetupCard() {
  const [start, setStart] = useState<StartResp | null>(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const [loading, setLoading] = useState(false);

  async function handleStart() {
    setError(null);
    setSuccess(false);
    setLoading(true);
    try {
      const res = await fetch("/api/mfa/totp/start", {
        method: "POST",
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data?.message ?? "Failed to start setup");
      setStart(data);
    } catch (e: any) {
      setError(e?.message ?? "Failed to start setup");
    } finally {
      setLoading(false);
    }
  }

  async function handleConfirm() {
    if (!start?.enrollmentToken) return;
    setError(null);
    setLoading(true);
    try {
      const res = await fetch("/api/mfa/totp/confirm", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ enrollmentToken: start.enrollmentToken, code }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data?.message ?? "Invalid code");
      setSuccess(true);
      setStart(null);
      setCode("");
    } catch (e: any) {
      setError(e?.message ?? "Failed to confirm");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card className="max-w-xl">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ShieldCheck className="h-5 w-5" />
          Authenticator App (TOTP)
        </CardTitle>
        <CardDescription>
          Use Google Authenticator / Microsoft Authenticator / Authy for 6-digit
          codes.
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-4">
        {error && (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertTitle>Setup Failed</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {success && (
          <Alert>
            <AlertTitle>Enabled</AlertTitle>
            <AlertDescription>
              Authenticator app MFA is now enabled.
            </AlertDescription>
          </Alert>
        )}

        {!start ? (
          <div className="space-y-2">
            <p className="text-sm text-muted-foreground">
              Start setup to generate a QR code, then confirm using a 6-digit
              code.
            </p>
            <Button onClick={handleStart} disabled={loading}>
              {loading ? "Starting..." : "Start setup"}
            </Button>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="rounded-lg border p-4 space-y-3">
              <div className="text-sm font-medium">Scan QR Code</div>
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img src={start.qrDataUrl} alt="TOTP QR" className="w-48 h-48" />
              <div className="text-xs text-muted-foreground">
                Can’t scan? Use manual key:
                <div className="font-mono break-all mt-1">
                  {start.manualKey}
                </div>
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium">Enter 6-digit code</label>
              <Input
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder="123456"
                inputMode="numeric"
              />
              <div className="flex gap-2">
                <Button
                  onClick={handleConfirm}
                  disabled={loading || code.length < 6}
                >
                  {loading ? "Confirming..." : "Confirm & enable"}
                </Button>
                <Button
                  variant="outline"
                  type="button"
                  onClick={() => setStart(null)}
                  disabled={loading}
                >
                  Cancel
                </Button>
              </div>
            </div>
          </div>
        )}
      </CardContent>

      <CardFooter className="text-xs text-muted-foreground">
        Codes refresh every 30 seconds.
      </CardFooter>
    </Card>
  );
}
