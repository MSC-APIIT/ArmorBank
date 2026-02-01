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
    <Card className="w-full max-w-md lg:max-w-2xl">
      <CardHeader className="text-center space-y-3">
        <CardTitle className="text-2xl lg:text-3xl font-headline flex items-center justify-center gap-2">
          <ShieldCheck className="h-6 w-6 text-primary" />
          Verify Your Identity
        </CardTitle>
        <CardDescription className="text-base">
          An extra security step is required for this login.
        </CardDescription>

        {titleMeta && (
          <div className="flex justify-center">
            <span
              className={[
                "inline-flex items-center gap-2 rounded-full border px-4 py-1.5 text-sm font-medium",
                titleMeta.className,
              ].join(" ")}
            >
              Risk Level: {titleMeta.label}
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
          <div className="space-y-3">
            <Label className="text-sm font-medium">
              Choose verification method
            </Label>
            <RadioGroup
              name="mfaMethodSelector"
              value={selectedMethod}
              className="grid grid-cols-1 md:grid-cols-3 gap-4"
              onValueChange={(v) => {
                setSelectedMethod(v as any);
                setBioError(null);
                setHint(null);
              }}
            >
              {/* Biometric Option */}
              <Label className="relative flex flex-col gap-3 rounded-lg border-2 p-5 cursor-pointer hover:bg-accent/50 has-[input:checked]:border-primary has-[input:checked]:bg-accent transition-all group">
                <div className="flex items-center gap-3">
                  <RadioGroupItem value="biometric" className="mt-0.5" />
                  <Fingerprint className="h-6 w-6 text-primary" />
                </div>
                <div className="space-y-1 pl-9">
                  <p className="font-semibold text-sm">Biometric</p>
                  <p className="text-xs text-muted-foreground">
                    Passkey or Face ID
                  </p>
                </div>
                <div className="absolute top-3 right-3">
                  <span className="text-xs font-medium text-primary opacity-0 group-has-[input:checked]:opacity-100 transition-opacity">
                    ✓ Selected
                  </span>
                </div>
              </Label>

              {/* Authenticator App Option */}
              <Label className="relative flex flex-col gap-3 rounded-lg border-2 p-5 cursor-not-allowed opacity-60 transition-all">
                <div className="flex items-center gap-3">
                  <RadioGroupItem value="app" disabled className="mt-0.5" />
                  <Smartphone className="h-6 w-6" />
                </div>
                <div className="space-y-1 pl-9">
                  <p className="font-semibold text-sm">Authenticator</p>
                  <p className="text-xs text-muted-foreground">Coming soon</p>
                </div>
              </Label>

              {/* Email Option */}
              <Label className="relative flex flex-col gap-3 rounded-lg border-2 p-5 cursor-pointer hover:bg-accent/50 has-[input:checked]:border-primary has-[input:checked]:bg-accent transition-all group">
                <div className="flex items-center gap-3">
                  <RadioGroupItem value="email" className="mt-0.5" />
                  <Mail className="h-6 w-6 text-primary" />
                </div>
                <div className="space-y-1 pl-9">
                  <p className="font-semibold text-sm">Email Code</p>
                  <p className="text-xs text-muted-foreground">
                    One-time password
                  </p>
                </div>
                <div className="absolute top-3 right-3">
                  <span className="text-xs font-medium text-primary opacity-0 group-has-[input:checked]:opacity-100 transition-opacity">
                    ✓ Selected
                  </span>
                </div>
              </Label>
            </RadioGroup>
          </div>

          {/* Biometric action */}
          {selectedMethod === "biometric" && (
            <div className="space-y-4 animate-in fade-in duration-300">
              <Button
                type="button"
                className="w-full h-12 text-base"
                size="lg"
                onClick={doBiometric}
                disabled={bioLoading}
              >
                {bioLoading ? (
                  <>
                    <RefreshCcw className="mr-2 h-5 w-5 animate-spin" />
                    Waiting for biometric...
                  </>
                ) : (
                  <>
                    <Fingerprint className="mr-2 h-5 w-5" />
                    Continue with Biometric
                  </>
                )}
              </Button>

              <div className="rounded-lg border bg-muted/40 p-4">
                <p className="text-sm text-muted-foreground text-center">
                  You'll be prompted to authenticate using your device's passkey
                  or biometric sensor.
                </p>
              </div>
            </div>
          )}

          {/* Code input */}
          {showCodeInput && (
            <div className="space-y-4 animate-in fade-in duration-300">
              {selectedMethod === "email" && (
                <Button
                  type="button"
                  variant="secondary"
                  className="w-full h-12 text-base"
                  size="lg"
                  onClick={sendEmailCode}
                  disabled={emailSending}
                >
                  {emailSending ? (
                    <>
                      <RefreshCcw className="mr-2 h-5 w-5 animate-spin" />
                      Sending code...
                    </>
                  ) : (
                    <>
                      <Mail className="mr-2 h-5 w-5" />
                      Send Email Code
                    </>
                  )}
                </Button>
              )}

              <div className="space-y-2">
                <Label htmlFor="mfaCode" className="text-sm font-medium">
                  Verification Code
                </Label>
                <Input
                  id="mfaCode"
                  name="mfaCode"
                  placeholder="000000"
                  className="h-12 text-center text-lg tracking-widest"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  maxLength={6}
                  required={showCodeInput}
                />
                <p className="text-xs text-muted-foreground">
                  Enter the 6-digit code from your{" "}
                  {selectedMethod === "email" ? "email" : "authenticator app"}.
                </p>
              </div>

              {hint && (
                <Alert className="bg-blue-50 border-blue-200">
                  <AlertCircle className="h-4 w-4 text-blue-600" />
                  <AlertDescription className="text-blue-800">
                    {hint}
                  </AlertDescription>
                </Alert>
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

          {/* Help section */}
          <div className="rounded-lg border bg-muted/40 p-4 space-y-2">
            <p className="text-sm font-medium">Need help?</p>
            <p className="text-xs text-muted-foreground">
              If you've lost access to your device, use{" "}
              <span className="font-medium text-foreground">Email Code</span> to
              verify your identity. You can add a new passkey after signing in.
            </p>
          </div>
        </CardContent>

        <CardFooter className="flex flex-col gap-3">
          {/* Only submit for code-based methods */}
          {showCodeInput ? (
            <VerifyButton disabled={selectedMethod === "app"} />
          ) : (
            <div className="w-full text-center py-2 text-sm text-muted-foreground">
              Click the button above to verify with biometric authentication.
            </div>
          )}

          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={() => router.push("/login")}
            className="w-full text-muted-foreground hover:text-foreground"
          >
            ← Back to login
          </Button>
        </CardFooter>
      </form>
    </Card>
  );
}
