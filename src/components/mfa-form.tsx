'use client';

import { useFormState, useFormStatus } from 'react-dom';
import { MfaState, verifyMfa } from '@/lib/actions';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { AlertCircle, Fingerprint, Mail, Smartphone } from 'lucide-react';
import React from 'react';
import { Alert, AlertDescription, AlertTitle } from './ui/alert';

function SubmitButton() {
  const { pending } = useFormStatus();
  return (
    <Button type="submit" className="w-full" disabled={pending}>
      {pending ? 'Verifying...' : 'Verify'}
    </Button>
  );
}

export function MfaForm() {
  const initialState: MfaState = {};
  const [state, dispatch] = useFormState(verifyMfa, initialState);
  const [selectedMethod, setSelectedMethod] = React.useState('biometric');
  
  const showCodeInput = selectedMethod === 'app' || selectedMethod === 'email';

  return (
    <Card className="w-full max-w-sm">
      <form action={dispatch}>
        <CardHeader className="text-center">
          <CardTitle className="text-2xl font-headline">Verify Your Identity</CardTitle>
          <CardDescription>An extra security step is required for this login.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <RadioGroup 
            name="mfaMethod" 
            defaultValue="biometric" 
            className="grid grid-cols-1 gap-4"
            onValueChange={setSelectedMethod}
            >
            <Label className="flex items-center space-x-3 rounded-md border p-4 cursor-pointer hover:bg-accent has-[input:checked]:border-primary has-[input:checked]:bg-accent">
              <RadioGroupItem value="biometric" />
              <Fingerprint className="h-5 w-5" />
              <span>Use Biometric</span>
            </Label>
            <Label className="flex items-center space-x-3 rounded-md border p-4 cursor-pointer hover:bg-accent has-[input:checked]:border-primary has-[input:checked]:bg-accent">
              <RadioGroupItem value="app" />
              <Smartphone className="h-5 w-5" />
              <span>Authenticator App</span>
            </Label>
            <Label className="flex items-center space-x-3 rounded-md border p-4 cursor-pointer hover:bg-accent has-[input:checked]:border-primary has-[input:checked]:bg-accent">
              <RadioGroupItem value="email" />
              <Mail className="h-5 w-5" />
              <span>Email One-Time Code</span>
            </Label>
          </RadioGroup>

          {showCodeInput && (
             <div className="space-y-2 animate-in fade-in duration-300">
                <Label htmlFor="mfaCode">Verification Code</Label>
                <Input 
                    id="mfaCode" 
                    name="mfaCode" 
                    placeholder="123456" 
                    required={showCodeInput}
                    aria-label="Verification Code"
                    />
                <p className="text-xs text-muted-foreground">Enter the 6-digit code from your authenticator app or email. (Hint: use 123456)</p>
             </div>
          )}

          {state?.error && (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertTitle>Verification Failed</AlertTitle>
              <AlertDescription>{state.error}</AlertDescription>
            </Alert>
          )}

        </CardContent>
        <CardFooter>
          <SubmitButton />
        </CardFooter>
      </form>
    </Card>
  );
}
