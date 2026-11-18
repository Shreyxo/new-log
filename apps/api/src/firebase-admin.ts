import { initializeApp, getApps, cert, type App } from "firebase-admin/app";
import { getAuth, type Auth, type DecodedIdToken, type UserRecord } from "firebase-admin/auth";

let firebaseAdminApp: App | null = null;
let firebaseAdminAuth: Auth | null = null;

function getServiceAccountCredentials() {
  // Option 1: Direct JSON service account key via environment variable
  const jsonKey = process.env.FIREBASE_SERVICE_ACCOUNT_KEY?.trim();
  if (jsonKey) {
    try {
      const parsed = JSON.parse(jsonKey);
      return {
        projectId: parsed.project_id || parsed.projectId,
        clientEmail: parsed.client_email || parsed.clientEmail,
        privateKey: (parsed.private_key || parsed.privateKey || "").replace(/\\n/g, "\n"),
      };
    } catch (err) {
      console.error("[FIREBASE-ADMIN] Failed to parse FIREBASE_SERVICE_ACCOUNT_KEY JSON:", err);
    }
  }

  // Option 2: Individual environment variables (common in Render / Vercel / Heroku)
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL?.trim();
  const rawPrivateKey = process.env.FIREBASE_PRIVATE_KEY?.trim();
  const projectId =
    process.env.FIREBASE_PROJECT_ID?.trim() ||
    process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID?.trim() ||
    "be-log-8f474";

  if (clientEmail && rawPrivateKey) {
    // Unescape escaped newlines if passed as single-line string
    const privateKey = rawPrivateKey.replace(/^["']|["']$/g, "").replace(/\\n/g, "\n");
    return {
      projectId,
      clientEmail,
      privateKey,
    };
  }

  return null;
}

export function isFirebaseAdminConfigured(): boolean {
  if (firebaseAdminAuth) return true;
  return getServiceAccountCredentials() !== null;
}

export function setFirebaseAdminForTesting(mockApp: App | null, mockAuth: Auth | null): void {
  firebaseAdminApp = mockApp;
  firebaseAdminAuth = mockAuth;
}

export function getFirebaseAdmin(): { app: App; auth: Auth } {
  if (firebaseAdminApp && firebaseAdminAuth) {
    return { app: firebaseAdminApp, auth: firebaseAdminAuth };
  }

  const existingApps = getApps();
  if (existingApps.length > 0 && existingApps[0]) {
    firebaseAdminApp = existingApps[0];
    firebaseAdminAuth = getAuth(firebaseAdminApp);
    return { app: firebaseAdminApp, auth: firebaseAdminAuth };
  }

  const creds = getServiceAccountCredentials();
  if (!creds) {
    throw new Error(
      "Firebase Admin is not configured. Please set FIREBASE_CLIENT_EMAIL and FIREBASE_PRIVATE_KEY (or FIREBASE_SERVICE_ACCOUNT_KEY).",
    );
  }

  firebaseAdminApp = initializeApp({
    credential: cert({
      projectId: creds.projectId,
      clientEmail: creds.clientEmail,
      privateKey: creds.privateKey,
    }),
    projectId: creds.projectId,
  });

  firebaseAdminAuth = getAuth(firebaseAdminApp);
  console.info(`[FIREBASE-ADMIN] Initialized successfully for project: ${creds.projectId}`);

  return { app: firebaseAdminApp, auth: firebaseAdminAuth };
}

export type VerifiedFirebaseToken = {
  uid: string;
  email: string;
  emailVerified: boolean;
  raw: DecodedIdToken;
};

export type VerifyTokenResult =
  | { success: true; token: VerifiedFirebaseToken }
  | {
      success: false;
      code: "INVALID_TOKEN" | "TOKEN_EXPIRED" | "TOKEN_REVOKED" | "CONFIG_ERROR";
      message: string;
    };

/**
 * Verifies a Firebase ID token using the Firebase Admin SDK.
 * Validates signature, issuer, audience, and expiration.
 * Does NOT trust any client-supplied claims without verification.
 */
export async function verifyFirebaseIdToken(
  idToken: string,
  checkRevoked = true,
): Promise<VerifyTokenResult> {
  if (!idToken || typeof idToken !== "string" || !idToken.trim()) {
    return {
      success: false,
      code: "INVALID_TOKEN",
      message: "Missing or invalid Firebase ID token.",
    };
  }

  try {
    const { auth } = getFirebaseAdmin();
    // checkRevoked verifies if the user's session was revoked
    const decoded = await auth.verifyIdToken(idToken.trim(), checkRevoked);

    if (!decoded.email) {
      return {
        success: false,
        code: "INVALID_TOKEN",
        message: "Firebase token does not contain an email address.",
      };
    }

    return {
      success: true,
      token: {
        uid: decoded.uid,
        email: decoded.email.toLowerCase(),
        emailVerified: Boolean(decoded.email_verified),
        raw: decoded,
      },
    };
  } catch (error: any) {
    const errorCode = error?.code || "";
    const errorMessage = error?.message || String(error);

    if (errorCode === "auth/id-token-expired") {
      return {
        success: false,
        code: "TOKEN_EXPIRED",
        message: "Your session has expired. Please sign in again.",
      };
    }
    if (errorCode === "auth/id-token-revoked") {
      return {
        success: false,
        code: "TOKEN_REVOKED",
        message: "Your session was revoked. Please sign in again.",
      };
    }
    if (errorMessage.includes("Firebase Admin is not configured")) {
      return {
        success: false,
        code: "CONFIG_ERROR",
        message: "Firebase Admin is not configured on the server.",
      };
    }

    return {
      success: false,
      code: "INVALID_TOKEN",
      message: "Invalid authentication token. Please sign in again.",
    };
  }
}

/**
 * Finds a Firebase user by email address.
 */
export async function getFirebaseUserByEmail(email: string): Promise<UserRecord | null> {
  const { auth } = getFirebaseAdmin();
  try {
    return await auth.getUserByEmail(email.trim().toLowerCase());
  } catch (error: any) {
    if (error?.code === "auth/user-not-found") {
      return null;
    }
    throw error;
  }
}

/**
 * Finds a Firebase user by Firebase UID.
 */
export async function getFirebaseUserByUid(uid: string): Promise<UserRecord | null> {
  const { auth } = getFirebaseAdmin();
  try {
    return await auth.getUser(uid);
  } catch (error: any) {
    if (error?.code === "auth/user-not-found") {
      return null;
    }
    throw error;
  }
}

/**
 * Creates a Firebase Authentication user.
 */
export async function createFirebaseUser(params: {
  email: string;
  password?: string;
  displayName?: string;
  emailVerified?: boolean;
}): Promise<UserRecord> {
  const { auth } = getFirebaseAdmin();
  return await auth.createUser({
    email: params.email.trim().toLowerCase(),
    password: params.password,
    displayName: params.displayName,
    emailVerified: params.emailVerified ?? false,
  });
}

/**
 * Updates a Firebase Authentication user.
 */
export async function updateFirebaseUser(
  uid: string,
  params: {
    password?: string;
    displayName?: string;
    emailVerified?: boolean;
  },
): Promise<UserRecord> {
  const { auth } = getFirebaseAdmin();
  return await auth.updateUser(uid, params);
}

/**
 * Deletes a Firebase Authentication user.
 * Used for safe cleanup if profile creation in PostgreSQL fails.
 */
export async function deleteFirebaseUser(uid: string): Promise<void> {
  const { auth } = getFirebaseAdmin();
  try {
    await auth.deleteUser(uid);
    console.info(`[FIREBASE-ADMIN] Cleaned up Firebase user uid=${uid}`);
  } catch (error) {
    console.error(`[FIREBASE-ADMIN] Failed to cleanup Firebase user uid=${uid}:`, error);
  }
}
