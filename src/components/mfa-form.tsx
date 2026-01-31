"use client";

import React, { useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useFormState, useFormStatus } from "react-dom";
import { startAuthentication } from "@simplewebauthn/browser";
import { verifyMfa, type MfaState } from "@/lib/actions";

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
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

import {
  AlertCircle,
  Fingerprint,
  Mail,
  Smartphone,
  ShieldCheck,
  RefreshCcw,
} from "lucide-react";

function VerifyButton({ disabled }: { disabled?: boolean }) {
  const { pending } = useFormStatus();
  return (
    <Button type="submit" className="w-full" disabled={disabled || pending}>
      {pending ? "Verifying..." : "Verify"}
    </Button>
  );
}

export function MfaForm() {
  const router = useRouter();
  const sp = useSearchParams();

  const mfaToken = sp.get("token") ?? "";
  const risk = sp.get("risk") ?? "";

  const preferred = (sp.get("preferred") ?? "email") as "email" | "passkey";

  const [selectedMethod, setSelectedMethod] = useState<
    "biometric" | "app" | "email"
  >(preferred === "passkey" ? "biometric" : "email");

  const [bioLoading, setBioLoading] = useState(false);
  const [emailSending, setEmailSending] = useState(false);
  const [bioError, setBioError] = useState<string | null>(null);
  const [hint, setHint] = useState<string | null>(null);

  const initialState: MfaState = {};
  const [state, dispatch] = useFormState(verifyMfa, initialState);

  const showCodeInput = selectedMethod === "app" || selectedMethod === "email";

  const titleMeta = useMemo(() => {
    const r = Number(risk || 0);
    if (!r) return null;
    if (r < 30)
      return {
        label: "Low",
        className: "bg-emerald-50 text-emerald-700 border-emerald-200",
      };
    if (r < 70)
      return {
        label: "Moderate",
        className: "bg-amber-50 text-amber-700 border-amber-200",
      };
    return {
      label: "High",
      className: "bg-red-50 text-red-700 border-red-200",
    };
  }, [risk]);

  const doBiometric = async () => {
    if (!mfaToken) {
      setBioError("Missing MFA token. Please go back and sign in again.");
      return;
    }

    setBioError(null);
    setHint(null);
    setBioLoading(true);

    try {
      // 1) Fetch server-generated WebAuthn options (challenge)
      const optRes = await fetch("/api/mfa/webauthn/options", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mfaToken }),
      });

      const optData = await optRes.json().catch(() => ({}));

      if (!optRes.ok) {
        if (optData?.code === "NO_PASSKEY") {
          setSelectedMethod("email");
          setBioError(
            "No passkey found for this account. Use Email Code instead.",
          );
          return;
        }
        setBioError(
          optData?.message ?? "Failed to start biometric verification.",
        );
        return;
      }

      // 2) Start browser passkey/authenticator flow
      const authResp = await startAuthentication(optData);

      // 3) Verify response on server
      const verifyRes = await fetch("/api/mfa/webauthn/verify", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mfaToken, response: authResp }),
      });

      const verifyData = await verifyRes.json().catch(() => ({}));

      if (!verifyRes.ok) {
        setBioError(verifyData?.message ?? "Biometric verification failed.");
        return;
      }

      router.push(verifyData.redirectTo ?? "/dashboard");
    } catch (e: any) {
      setBioError(e?.message ?? "Biometric failed. Try Email Code.");
    } finally {
      setBioLoading(false);
    }
  };

  const sendEmailCode = async () => {
    if (!mfaToken) {
      setHint(null);
      setBioError("Missing MFA token. Please go back and sign in again.");
      return;
    }

    setBioError(null);
    setHint(null);
    setEmailSending(true);

    try {
      const res = await fetch("/api/mfa/email/request", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mfaToken }),
      });

      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setBioError(data?.message ?? "Could not send email code.");
        return;
      }

      setHint("We sent a 6-digit code to your email. Enter it below.");
    } catch {
      setBioError("Could not send email code. Try again.");
    } finally {
      setEmailSending(false);
    }
  };

  return (
    <Card className="w-full max-w-sm">
      <CardHeader className="text-center space-y-2">
        <CardTitle className="text-2xl font-headline flex items-center justify-center gap-2">
          <ShieldCheck className="h-5 w-5 text-primary" />
          Verify Your Identity
        </CardTitle>
        <CardDescription>
          An extra security step is required for this login.
        </CardDescription>

        {titleMeta && (
          <div className="flex justify-center">
            <span
              className={[
                "inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium",
                titleMeta.className,
              ].join(" ")}
            >
              Risk: {titleMeta.label}
              {risk ? <span className="opacity-70">({risk})</span> : null}
            </span>
          </div>
        )}
      </CardHeader>

      <form action={dispatch}>
        {/* Hidden fields for server action */}
        <input type="hidden" name="mfaToken" value={mfaToken} />
        <input type="hidden" name="mfaMethod" value={selectedMethod} />

        <CardContent className="space-y-6">
          {/* Method selector */}
          <RadioGroup
            name="mfaMethodSelector"
            value={selectedMethod}
            className="grid grid-cols-1 gap-3"
            onValueChange={(v) => {
              setSelectedMethod(v as any);
              setBioError(null);
              setHint(null);
            }}
          >
            <Label className="flex items-center justify-between rounded-md border p-4 cursor-pointer hover:bg-accent has-[input:checked]:border-primary has-[input:checked]:bg-accent">
              <span className="flex items-center gap-3">
                <RadioGroupItem value="biometric" />
                <Fingerprint className="h-5 w-5" />
                <span className="font-medium">Use Biometric (Passkey)</span>
              </span>
              <span className="text-xs text-muted-foreground">Recommended</span>
            </Label>

            <Label className="flex items-center justify-between rounded-md border p-4 cursor-pointer hover:bg-accent has-[input:checked]:border-primary has-[input:checked]:bg-accent">
              <span className="flex items-center gap-3">
                <RadioGroupItem value="app" />
                <Smartphone className="h-5 w-5" />
                <span className="font-medium">Authenticator App</span>
              </span>
              <span className="text-xs text-muted-foreground">Coming soon</span>
            </Label>

            <Label className="flex items-center justify-between rounded-md border p-4 cursor-pointer hover:bg-accent has-[input:checked]:border-primary has-[input:checked]:bg-accent">
              <span className="flex items-center gap-3">
                <RadioGroupItem value="email" />
                <Mail className="h-5 w-5" />
                <span className="font-medium">Email One-Time Code</span>
              </span>
              <span className="text-xs text-muted-foreground">Backup</span>
            </Label>
          </RadioGroup>

          {/* Biometric action */}
          {selectedMethod === "biometric" && (
            <div className="space-y-3">
              <Button
                type="button"
                className="w-full"
                onClick={doBiometric}
                disabled={bioLoading}
              >
                {bioLoading ? (
                  <>
                    <RefreshCcw className="mr-2 h-4 w-4 animate-spin" />
                    Waiting for biometric...
                  </>
                ) : (
                  <>
                    <Fingerprint className="mr-2 h-4 w-4" />
                    Continue with Biometric
                  </>
                )}
              </Button>

              <p className="text-xs text-muted-foreground text-center">
                You’ll be asked to confirm with your device passkey or
                biometric.
              </p>
            </div>
          )}

          {/* Code input */}
          {showCodeInput && (
            <div className="space-y-3 animate-in fade-in duration-300">
              {selectedMethod === "email" && (
                <Button
                  type="button"
                  variant="secondary"
                  className="w-full"
                  onClick={sendEmailCode}
                  disabled={emailSending}
                >
                  {emailSending ? (
                    <>
                      <RefreshCcw className="mr-2 h-4 w-4 animate-spin" />
                      Sending code...
                    </>
                  ) : (
                    <>
                      <Mail className="mr-2 h-4 w-4" />
                      Send Email Code
                    </>
                  )}
                </Button>
              )}

              <div className="space-y-2">
                <Label htmlFor="mfaCode">Verification Code</Label>
                <Input
                  id="mfaCode"
                  name="mfaCode"
                  placeholder="123456"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  required={showCodeInput}
                />
                <p className="text-xs text-muted-foreground">
                  Enter the 6-digit code from your{" "}
                  {selectedMethod === "email" ? "email" : "authenticator app"}.
                </p>
              </div>

              {hint && (
                <div className="rounded-md border bg-muted/40 px-3 py-2 text-xs text-muted-foreground">
                  {hint}
                </div>
              )}
            </div>
          )}

          {/* Errors */}
          {(bioError || state?.error) && (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertTitle>Verification Failed</AlertTitle>
              <AlertDescription>{bioError ?? state?.error}</AlertDescription>
            </Alert>
          )}

          {/* Lightweight info */}
          <div className="rounded-md border bg-muted/40 px-3 py-2 text-xs text-muted-foreground">
            Tip: If you lost your device, use{" "}
            <span className="font-medium">Email One-Time Code</span> and then
            add a new passkey after you sign in.
          </div>
        </CardContent>

        <CardFooter>
          {/* Only submit for code-based methods */}
          {showCodeInput ? (
            <VerifyButton disabled={selectedMethod === "app"} />
          ) : (
            <div className="w-full text-center text-xs text-muted-foreground">
              Biometric verification does not require a code.
            </div>
          )}
        </CardFooter>
      </form>
    </Card>
  );
}
