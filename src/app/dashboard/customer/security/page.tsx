import TotpSetupCard from "@/components/totp-setup-card";

export default function SecurityPage() {
  return (
    <div className="w-full p-6">
      <div className="mx-auto w-full max-w-xl space-y-6">
        <h1 className="text-2xl font-bold text-center">Security</h1>
        <TotpSetupCard />
      </div>
    </div>
  );
}
