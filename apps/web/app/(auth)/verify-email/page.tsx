import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { AuthError, verifyEmail } from "@/lib/services/auth";
import { VerifyEmailView } from "@/components/auth/verify-email-view";

export const metadata = { title: "Verify email — Digital BE Log Book" };

export default async function VerifyEmailPage({
  searchParams,
}: {
  searchParams?: { token?: string; oobCode?: string; mode?: string };
}) {
  const token = searchParams?.token;
  const oobCode = searchParams?.oobCode;
  const mode = searchParams?.mode;

  let errorMessage: string | null = null;
  let errorCode: string | null = null;
  let verifiedEmail: string | null = null;
  let alreadyVerified = false;

  if (token) {
    try {
      const result = await verifyEmail(token);
      verifiedEmail = result.email;
      alreadyVerified = Boolean(result.alreadyVerified);
    } catch (e) {
      if (e instanceof AuthError) {
        errorMessage = e.message;
        errorCode = e.code;
      } else {
        errorMessage = "We could not verify this link. Please request a new one.";
        errorCode = "UNKNOWN";
      }
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Email verification</CardTitle>
        <CardDescription>Activate your account to sign in.</CardDescription>
      </CardHeader>
      <CardContent>
        <VerifyEmailView
          verifiedEmail={verifiedEmail}
          alreadyVerified={alreadyVerified}
          errorMessage={errorMessage}
          errorCode={errorCode}
          oobCode={oobCode}
          mode={mode}
        />
      </CardContent>
    </Card>
  );
}
