import { getSession } from "@/lib/session";
import { redirect } from "next/navigation";
import HomeContent from "./home-content";

export default async function Home() {
  const session = await getSession();

  if (session) {
    redirect(`/dashboard/${session.user.role}`);
  }

  return <HomeContent />;
}
