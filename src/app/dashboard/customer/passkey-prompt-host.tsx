"use client";

import { PasskeyPromptModal } from "@/components/PasskeyPromptModal";
import { startRegistration } from "@simplewebauthn/browser";
import React, { useEffect, useMemo, useState } from "react";

export function PasskeyPromptHost({
  shouldPrompt,
  userId,
  hasPasskey = false,
  forceOpenKey,
}: {
  shouldPrompt: boolean;
  userId?: string;
  hasPasskey?: boolean;
  forceOpenKey?: number;
}) {
  const [open, setOpen] = useState(false);

  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState<string | null>(null);

  useEffect(() => {
    if (shouldPrompt && !hasPasskey) setOpen(true);
  }, [shouldPrompt, hasPasskey]);

  useEffect(() => {
    if (typeof forceOpenKey === "number" && forceOpenKey > 0) {
      setOpen(true);
    }
  }, [forceOpenKey]);

  useEffect(() => {
    if (!open) return;
    if (hasPasskey) {
      setStatus(
        "Passkey already set up ✅ You can add another one if you want.",
      );
    } else {
      setStatus(null);
    }
  }, [open, hasPasskey]);

  return (
    <PasskeyPromptModal
      open={open}
      loading={loading}
      status={status}
      onSkip={() => {
        if (loading) return;
        setOpen(false);
      }}
      onAddPasskey={async () => {
        try {
          setLoading(true);
          setStatus(
            hasPasskey
              ? "Preparing another passkey registration..."
              : "Preparing passkey registration...",
          );

          const uid = userId;
          if (!uid) throw new Error("Missing userId");

          const optionsRes = await fetch("/api/mfa/webauthn/register/options", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ userId: uid }),
          });

          if (!optionsRes.ok) {
            const err = await optionsRes.json().catch(() => ({}));
            throw new Error(
              err?.message ?? "Failed to get registration options",
            );
          }

          const options = await optionsRes.json();

          setStatus("Waiting for Face ID / Fingerprint / Windows Hello...");

          const registrationResponse = await startRegistration(options);

          setStatus("Saving passkey...");

          const verifyRes = await fetch("/api/mfa/webauthn/register/verify", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ userId: uid, registrationResponse }),
          });

          if (!verifyRes.ok) {
            const err = await verifyRes.json().catch(() => ({}));
            throw new Error(err?.message ?? "Passkey verification failed");
          }

          setStatus("Passkey added ✅");
          setTimeout(() => setOpen(false), 700);
        } catch (e: any) {
          setStatus(e?.message ?? "Passkey registration failed");
        } finally {
          setLoading(false);
        }
      }}
    />
  );
}
