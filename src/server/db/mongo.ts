import { MongoClient, Db } from "mongodb";
import { env } from "@/server/config/env";

declare global {
  // eslint-disable-next-line no-var
  var __mongoClientPromise: Promise<MongoClient> | undefined;
}

const uri = env.MONGODB_URI;

async function userHasPasskey(userId: string) {
  const db = await getDb();
  const webauthnCreds = db.collection("webauthn_credentials");
  const count = await webauthnCreds.countDocuments({ userId: userId as any });
  return count > 0;
}

function getClientPromise() {
  if (!globalThis.__mongoClientPromise) {
    const client = new MongoClient(uri, {
      maxPoolSize: 10,
    });
    globalThis.__mongoClientPromise = client.connect();
  }
  return globalThis.__mongoClientPromise;
}

export async function getDb(): Promise<Db> {
  const client = await getClientPromise();
  return client.db(env.MONGODB_DB);
}
