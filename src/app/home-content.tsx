import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { PlaceHolderImages } from '@/lib/placeholder-images';
import { Activity, ShieldCheck, Users } from 'lucide-react';
import Image from 'next/image';
import Link from 'next/link';

export default function HomeContent() {
  const heroImage = PlaceHolderImages.find((img) => img.id === 'hero-background');

  return (
    <div className="flex flex-col min-h-screen">
      <header className="sticky top-0 z-50 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container flex h-14 items-center">
          <Link href="/" className="mr-6 flex items-center space-x-2">
            <ShieldCheck className="h-6 w-6 text-primary" />
            <span className="font-bold font-headline">BankAuth</span>
          </Link>
          <nav className="flex-1" />
          <div className="flex items-center space-x-2">
            <Button variant="ghost" asChild>
              <Link href="/login">Sign In</Link>
            </Button>
            <Button asChild>
              <Link href="/login">Secure Access</Link>
            </Button>
          </div>
        </div>
      </header>
      <main className="flex-1">
        <section className="relative w-full py-20 md:py-32 lg:py-40">
          {heroImage && (
            <Image
              src={heroImage.imageUrl}
              alt={heroImage.description}
              fill
              className="object-cover"
              priority
              data-ai-hint={heroImage.imageHint}
            />
          )}
          <div className="absolute inset-0 bg-background/80" />
          <div className="container relative text-center">
            <div className="flex flex-col items-center">
              <h1 className="text-4xl font-extrabold tracking-tighter sm:text-5xl md:text-6xl lg:text-7xl font-headline">
                The Future of Secure Banking
              </h1>
              <p className="mx-auto max-w-[700px] text-lg text-muted-foreground md:text-xl mt-4">
                Our platform provides cutting-edge, adaptive authentication to protect banking customers and their assets without compromising on user experience.
              </p>
              <div className="mt-8">
                <Button size="lg" asChild>
                  <Link href="/login">Access Your Account</Link>
                </Button>
              </div>
            </div>
          </div>
        </section>

        <section className="w-full py-12 md:py-24 lg:py-32 bg-secondary">
          <div className="container grid gap-12 px-4 md:px-6">
            <div className="flex flex-col items-center justify-center space-y-4 text-center">
              <div className="space-y-2">
                <div className="inline-block rounded-lg bg-muted px-3 py-1 text-sm">Key Security Features</div>
                <h2 className="text-3xl font-bold tracking-tighter sm:text-5xl font-headline">Unparalleled Security, Seamless Access</h2>
                <p className="max-w-[900px] text-muted-foreground md:text-xl/relaxed lg:text-base/relaxed xl:text-xl/relaxed">
                  Our platform integrates multiple layers of security to provide robust protection against unauthorized access to banking services.
                </p>
              </div>
            </div>
            <div className="mx-auto grid items-start gap-8 sm:max-w-4xl sm:grid-cols-2 md:gap-12 lg:max-w-5xl lg:grid-cols-3">
              <Card className="bg-background">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <ShieldCheck className="w-6 h-6 text-primary" />
                    Multi-Factor Authentication
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <p>Go beyond passwords with adaptive MFA. We support biometrics, authenticator apps, and one-time codes, intelligently selecting the best method for each situation.</p>
                </CardContent>
              </Card>
              <Card className="bg-background">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Activity className="w-6 h-6 text-primary" />
                    Fraud &amp; Risk Engine
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <p>Our custom engine analyzes every login attempt, calculating a real-time risk score based on IP, device, and user behavior to proactively block threats before they happen.</p>
                </CardContent>
              </Card>
              <Card className="bg-background">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Users className="w-6 h-6 text-primary" />
                    Role-Based Access
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <p>Enforce granular permissions with server-side role validation. Ensure users and staff only access the data and functions they are authorized for.</p>
                </CardContent>
              </Card>
            </div>
          </div>
        </section>
      </main>
      <footer className="py-6 border-t">
        <div className="container text-center text-sm text-muted-foreground">
          © {new Date().getFullYear()} BankAuth. All Rights Reserved.
        </div>
      </footer>
    </div>
  );
}
