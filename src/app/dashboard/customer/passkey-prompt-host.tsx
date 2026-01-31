"use client";

import { PasskeyPromptModal } from "@/components/PasskeyPromptModal";
import { startRegistration } from "@simplewebauthn/browser";
import React, { useEffect, useState } from "react";

export function PasskeyPromptHost({
  shouldPrompt,
  userId,
}: {
  shouldPrompt: boolean;
  userId?: string;
}) {
  const [open, setOpen] = useState(shouldPrompt);
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState<string | null>(null);

  useEffect(() => {
    setOpen(shouldPrompt);
  }, [shouldPrompt]);

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
          setStatus("Preparing passkey registration...");
          // 1) get session userId from a prop OR from an endpoint
          // Since you already have session in server component, pass it in:
          // <PasskeyPromptHost shouldPrompt={...} userId={session.user.id} />
          const uid = userId;
          if (!uid) throw new Error("Missing userId");
          // 2) fetch registration options
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

          // 3) browser WebAuthn prompt
          const registrationResponse = await startRegistration(options);

          setStatus("Saving passkey...");

          // 4) verify + save in DB
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
