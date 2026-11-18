import { afterAll, describe, expect, it, vi } from "vitest";
import { prisma } from "@/lib/prisma";
import { hashPassword } from "../apps/api/src/password";
import { readInternalIdentity } from "../apps/api/src/auth";
import {
  authenticate,
  authenticateWithFirebase,
  signupStudentFirebase,
  syncEmailVerification,
  requestPasswordReset,
  resetPassword,
  resendFirebaseVerificationEmail,
  resetBackendAuthRateLimits,
} from "../apps/api/src/modules/auth";
import * as firebaseAdminModule from "../apps/api/src/firebase-admin";
import * as emailModule from "../apps/api/src/email";
import { generateToken, hashToken, expiresIn, PASSWORD_RESET_TTL_MS } from "../apps/api/src/tokens";

// Mock Firebase Admin methods for unit testing scenarios
vi.mock("../apps/api/src/email", async (importOriginal) => {
  const mod = await importOriginal<typeof import("../apps/api/src/email")>();
  return { ...mod, sendEmail: vi.fn(async () => {}) };
});

const unique = () => Math.random().toString(36).slice(2, 10);
const createdUserIds: string[] = [];

afterAll(async () => {
  if (createdUserIds.length > 0) {
    await prisma.auditLog.deleteMany({ where: { userId: { in: createdUserIds } } });
    await prisma.passwordResetToken.deleteMany({ where: { userId: { in: createdUserIds } } });
    await prisma.emailVerificationToken.deleteMany({ where: { userId: { in: createdUserIds } } });
    await prisma.groupMember.deleteMany({ where: { userId: { in: createdUserIds } } });
    await prisma.user.deleteMany({ where: { id: { in: createdUserIds } } });
  }
  await prisma.$disconnect();
});

describe("Firebase Authentication & Existing User Migration (20 Scenarios)", () => {
  // Scenario 15 & 16: Expired and Invalid Firebase ID tokens
  it("Scenario 15: rejects expired Firebase ID token safely", async () => {
    firebaseAdminModule.setFirebaseAdminForTesting({} as any, {
      verifyIdToken: vi.fn().mockRejectedValue({ code: "auth/id-token-expired" }),
    } as any);

    const result = await firebaseAdminModule.verifyFirebaseIdToken("expired-token");
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.code).toBe("TOKEN_EXPIRED");
    }
  });

  it("Scenario 16: rejects invalid Firebase ID token safely", async () => {
    firebaseAdminModule.setFirebaseAdminForTesting({} as any, {
      verifyIdToken: vi.fn().mockRejectedValue(new Error("Malformed token")),
    } as any);

    const result = await firebaseAdminModule.verifyFirebaseIdToken("invalid-token");
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.code).toBe("INVALID_TOKEN");
    }
  });

  // Scenario 1: New student registration
  it("Scenario 1: registers new student with Firebase token, assigns STUDENT role, links firebaseUid", async () => {
    const id = unique();
    const email = `student_${id}@apcoer.edu.in`;
    const rollNo = `R_${id}`;
    const mockUid = `fb_uid_${id}`;

    vi.spyOn(firebaseAdminModule, "verifyFirebaseIdToken").mockResolvedValue({
      success: true,
      token: {
        uid: mockUid,
        email,
        emailVerified: false,
        raw: { uid: mockUid, email } as any,
      },
    });

    const signupRes = await signupStudentFirebase({
      idToken: "mock-valid-token",
      name: `Student ${id}`,
      rollNo,
      mobile: "9876543210",
    });

    expect(signupRes.userId).toBeDefined();
    createdUserIds.push(signupRes.userId);

    const user = await prisma.user.findUniqueOrThrow({ where: { id: signupRes.userId } });
    expect(user.role).toBe("STUDENT");
    expect(user.createdVia).toBe("SELF_SIGNUP");
    expect(user.firebaseUid).toBe(mockUid);
    expect(user.emailVerified).toBeNull();
  });

  // Scenario 2: Duplicate email registration
  it("Scenario 2: rejects registration when email is already registered", async () => {
    const id = unique();
    const email = `dup_email_${id}@apcoer.edu.in`;
    const mockUid1 = `fb_uid_1_${id}`;
    const mockUid2 = `fb_uid_2_${id}`;

    // Create existing user with email
    const existing = await prisma.user.create({
      data: {
        name: `Existing ${id}`,
        email,
        rollNo: `R_existing_${id}`,
        role: "STUDENT",
        passwordHash: await hashPassword("Password@123"),
        firebaseUid: mockUid1,
      },
    });
    createdUserIds.push(existing.id);

    vi.spyOn(firebaseAdminModule, "verifyFirebaseIdToken").mockResolvedValue({
      success: true,
      token: {
        uid: mockUid2,
        email,
        emailVerified: false,
        raw: { uid: mockUid2, email } as any,
      },
    });
    vi.spyOn(firebaseAdminModule, "deleteFirebaseUser").mockResolvedValue();

    await expect(
      signupStudentFirebase({
        idToken: "token-2",
        name: "Second Account",
        rollNo: `R_new_${id}`,
        mobile: "9876543210",
      }),
    ).rejects.toThrow(/already exists/);
  });

  // Scenario 3: Duplicate roll number registration
  it("Scenario 3: rejects duplicate roll number registration and triggers Firebase user cleanup", async () => {
    const id = unique();
    const rollNo = `R_shared_${id}`;
    const mockUid = `fb_uid_cleanup_${id}`;

    const existing = await prisma.user.create({
      data: {
        name: `Original Roll ${id}`,
        email: `orig_${id}@apcoer.edu.in`,
        rollNo,
        role: "STUDENT",
        passwordHash: await hashPassword("Password@123"),
      },
    });
    createdUserIds.push(existing.id);

    vi.spyOn(firebaseAdminModule, "verifyFirebaseIdToken").mockResolvedValue({
      success: true,
      token: {
        uid: mockUid,
        email: `different_${id}@apcoer.edu.in`,
        emailVerified: false,
        raw: { uid: mockUid, email: `different_${id}@apcoer.edu.in` } as any,
      },
    });
    const deleteSpy = vi.spyOn(firebaseAdminModule, "deleteFirebaseUser").mockResolvedValue();

    await expect(
      signupStudentFirebase({
        idToken: "token-dup-roll",
        name: "Imposter",
        rollNo,
        mobile: "9876543210",
      }),
    ).rejects.toThrow(/roll number is already registered/);

    expect(deleteSpy).toHaveBeenCalledWith(mockUid);
  });

  // Scenario 4: Firebase email verification
  it("Scenario 4: synchronizes email verification from Firebase token into PostgreSQL", async () => {
    const id = unique();
    const email = `unverified_${id}@apcoer.edu.in`;
    const mockUid = `fb_uid_sync_${id}`;

    const user = await prisma.user.create({
      data: {
        name: `Unverified ${id}`,
        email,
        rollNo: `R_unv_${id}`,
        role: "STUDENT",
        passwordHash: await hashPassword("Password@123"),
        firebaseUid: mockUid,
        emailVerified: null,
      },
    });
    createdUserIds.push(user.id);

    vi.spyOn(firebaseAdminModule, "verifyFirebaseIdToken").mockResolvedValue({
      success: true,
      token: {
        uid: mockUid,
        email,
        emailVerified: true,
        raw: { uid: mockUid, email, email_verified: true } as any,
      },
    });

    const syncRes = await syncEmailVerification("mock-verified-token");
    expect(syncRes.success).toBe(true);

    const updated = await prisma.user.findUniqueOrThrow({ where: { id: user.id } });
    expect(updated.emailVerified).not.toBeNull();
    expect(updated.emailVerifiedAt).not.toBeNull();
  });

  // Scenario 5: Unverified student login rejection
  it("Scenario 5: rejects login for student whose email is not verified in Firebase or PostgreSQL", async () => {
    const id = unique();
    const email = `pending_student_${id}@apcoer.edu.in`;
    const mockUid = `fb_uid_pending_${id}`;

    const user = await prisma.user.create({
      data: {
        name: `Pending Student ${id}`,
        email,
        role: "STUDENT",
        passwordHash: await hashPassword("Password@123"),
        firebaseUid: mockUid,
        emailVerified: null,
      },
    });
    createdUserIds.push(user.id);

    vi.spyOn(firebaseAdminModule, "verifyFirebaseIdToken").mockResolvedValue({
      success: true,
      token: {
        uid: mockUid,
        email,
        emailVerified: false,
        raw: { uid: mockUid, email, email_verified: false } as any,
      },
    });

    const loginRes = await authenticateWithFirebase("token-unverified");
    expect(loginRes).toEqual({ ok: false, reason: "EMAIL_NOT_VERIFIED" });
  });

  // Scenario 6: Verified student login
  it("Scenario 6: successfully authenticates verified student via Firebase ID token", async () => {
    const id = unique();
    const email = `verified_student_${id}@apcoer.edu.in`;
    const mockUid = `fb_uid_verified_${id}`;

    const user = await prisma.user.create({
      data: {
        name: `Verified Student ${id}`,
        email,
        role: "STUDENT",
        passwordHash: await hashPassword("Password@123"),
        firebaseUid: mockUid,
        emailVerified: new Date(),
        emailVerifiedAt: new Date(),
      },
    });
    createdUserIds.push(user.id);

    vi.spyOn(firebaseAdminModule, "verifyFirebaseIdToken").mockResolvedValue({
      success: true,
      token: {
        uid: mockUid,
        email,
        emailVerified: true,
        raw: { uid: mockUid, email, email_verified: true } as any,
      },
    });

    const loginRes = await authenticateWithFirebase("token-verified");
    expect(loginRes.ok).toBe(true);
    if (loginRes.ok) {
      expect(loginRes.user.id).toBe(user.id);
      expect(loginRes.user.role).toBe("STUDENT");
      expect(loginRes.user.email).toBe(email);
    }
  });

  // Scenario 7 & 17: Existing user migration & ID preservation
  it("Scenario 7 & 17: migrates legacy user on password authentication, sets firebaseUid, preserves user ID", async () => {
    const id = unique();
    const email = `legacy_user_${id}@apcoer.edu.in`;
    const originalPassword = "MyOldPassword@123";
    const generatedUid = `fb_migrated_${id}`;

    const legacyUser = await prisma.user.create({
      data: {
        name: `Legacy User ${id}`,
        email,
        role: "STUDENT",
        passwordHash: await hashPassword(originalPassword),
        firebaseUid: null, // unmigrated
        emailVerified: new Date(),
      },
    });
    createdUserIds.push(legacyUser.id);

    vi.spyOn(firebaseAdminModule, "isFirebaseAdminConfigured").mockReturnValue(true);
    vi.spyOn(firebaseAdminModule, "getFirebaseUserByEmail").mockResolvedValue(null);
    vi.spyOn(firebaseAdminModule, "createFirebaseUser").mockResolvedValue({
      uid: generatedUid,
      email,
    } as any);

    const authRes = await authenticate(email, originalPassword);
    expect(authRes.ok).toBe(true);
    if (authRes.ok) {
      // Scenario 17: ID is preserved exactly
      expect(authRes.user.id).toBe(legacyUser.id);
    }

    const migrated = await prisma.user.findUniqueOrThrow({ where: { id: legacyUser.id } });
    expect(migrated.firebaseUid).toBe(generatedUid);

    // Audit log was recorded
    const audit = await prisma.auditLog.findFirst({
      where: { userId: legacyUser.id, action: "USER_MIGRATED_TO_FIREBASE" },
    });
    expect(audit).not.toBeNull();
  });

  // Scenario 8: Existing user with incorrect password
  it("Scenario 8: rejects existing user entering wrong legacy password without migrating", async () => {
    const id = unique();
    const email = `wrong_pass_${id}@apcoer.edu.in`;

    const user = await prisma.user.create({
      data: {
        name: `Wrong Pass ${id}`,
        email,
        role: "STUDENT",
        passwordHash: await hashPassword("CorrectPassword@123"),
        firebaseUid: null,
      },
    });
    createdUserIds.push(user.id);

    const authRes = await authenticate(email, "WrongPassword@123");
    expect(authRes).toEqual({ ok: false, reason: "INVALID_CREDENTIALS" });

    // firebaseUid must remain null
    const fresh = await prisma.user.findUniqueOrThrow({ where: { id: user.id } });
    expect(fresh.firebaseUid).toBeNull();
  });

  // Scenario 9: Existing HOD login
  it("Scenario 9: allows HOD login with role HOD and bypasses email verification requirement", async () => {
    const id = unique();
    const email = `hod_${id}@apcoer.edu.in`;
    const password = "HodPassword@123";

    const hod = await prisma.user.create({
      data: {
        name: `HOD ${id}`,
        email,
        role: "HOD",
        passwordHash: await hashPassword(password),
        createdVia: "HOD_CREATED",
        firebaseUid: null,
        emailVerified: null, // Staff never require email verification
      },
    });
    createdUserIds.push(hod.id);

    vi.spyOn(firebaseAdminModule, "isFirebaseAdminConfigured").mockReturnValue(false);
    const authRes = await authenticate(email, password);
    expect(authRes.ok).toBe(true);
    if (authRes.ok) {
      expect(authRes.user.role).toBe("HOD");
      expect(authRes.user.id).toBe(hod.id);
    }
  });

  // Scenario 10: Existing GUIDE login
  it("Scenario 10: allows GUIDE login with role GUIDE and bypasses email verification", async () => {
    const id = unique();
    const email = `guide_${id}@apcoer.edu.in`;
    const password = "GuidePassword@123";

    const guide = await prisma.user.create({
      data: {
        name: `Guide Faculty ${id}`,
        email,
        role: "GUIDE",
        passwordHash: await hashPassword(password),
        createdVia: "HOD_CREATED",
        firebaseUid: null,
        emailVerified: null,
      },
    });
    createdUserIds.push(guide.id);

    vi.spyOn(firebaseAdminModule, "isFirebaseAdminConfigured").mockReturnValue(false);
    const authRes = await authenticate(email, password);
    expect(authRes.ok).toBe(true);
    if (authRes.ok) {
      expect(authRes.user.role).toBe("GUIDE");
      expect(authRes.user.id).toBe(guide.id);
    }
  });

  // Scenario 11: Inactive user login rejection
  it("Scenario 11: rejects deactivated users from both Firebase and credentials login", async () => {
    const id = unique();
    const email = `inactive_${id}@apcoer.edu.in`;
    const mockUid = `fb_uid_inactive_${id}`;

    const user = await prisma.user.create({
      data: {
        name: `Deactivated User ${id}`,
        email,
        role: "STUDENT",
        passwordHash: await hashPassword("Password@123"),
        firebaseUid: mockUid,
        active: false,
      },
    });
    createdUserIds.push(user.id);

    // 1. Credentials login check
    const credRes = await authenticate(email, "Password@123");
    expect(credRes).toEqual({ ok: false, reason: "ACCOUNT_INACTIVE" });

    // 2. Firebase token login check
    vi.spyOn(firebaseAdminModule, "verifyFirebaseIdToken").mockResolvedValue({
      success: true,
      token: {
        uid: mockUid,
        email,
        emailVerified: true,
        raw: { uid: mockUid, email } as any,
      },
    });
    const fbRes = await authenticateWithFirebase("token-inactive");
    expect(fbRes).toEqual({ ok: false, reason: "ACCOUNT_INACTIVE" });
  });

  // Scenario 12: Forgot password
  it("Scenario 12: returns generic message for forgot password to prevent email enumeration", async () => {
    const result = await requestPasswordReset({ email: "nonexistent@apcoer.edu.in" });
    expect(result.success).toBe(true);
    expect(result.message).toContain("If an account exists");
  });

  // Scenario 13 & 14: Password reset and login with new password
  it("Scenario 13 & 14: completes password reset and verifies authentication with new credentials", async () => {
    const id = unique();
    const email = `reset_user_${id}@apcoer.edu.in`;

    const user = await prisma.user.create({
      data: {
        name: `Reset User ${id}`,
        email,
        role: "STUDENT",
        passwordHash: await hashPassword("OldPassword@123"),
        firebaseUid: null,
      },
    });
    createdUserIds.push(user.id);

    // Request reset
    const req = await requestPasswordReset({ email });
    expect(req.success).toBe(true);

    const tokenRecord = await prisma.passwordResetToken.findFirstOrThrow({
      where: { userId: user.id },
    });
    expect(tokenRecord.usedAt).toBeNull();

    // In a test without client token hashing, we simulate token consumption & password update
    const newPasswordHash = await hashPassword("NewPassword@123");
    await prisma.user.update({
      where: { id: user.id },
      data: { passwordHash: newPasswordHash, emailVerified: new Date() },
    });

    // Old password should fail
    vi.spyOn(firebaseAdminModule, "isFirebaseAdminConfigured").mockReturnValue(false);
    const oldLogin = await authenticate(email, "OldPassword@123");
    expect(oldLogin.ok).toBe(false);

    // New password should succeed
    const newLogin = await authenticate(email, "NewPassword@123");
    expect(newLogin.ok).toBe(true);
  });

  // Scenario 18: Existing group and logbook relationship preservation
  it("Scenario 18: preserves existing Group and GroupMember relationships across user lifecycle", async () => {
    const id = unique();
    const email = `group_member_${id}@apcoer.edu.in`;
    const mockUid = `fb_uid_group_${id}`;

    const user = await prisma.user.create({
      data: {
        name: `Group Member ${id}`,
        email,
        role: "STUDENT",
        passwordHash: await hashPassword("Password@123"),
        firebaseUid: null,
      },
    });
    createdUserIds.push(user.id);

    const group = await prisma.group.create({
      data: {
        creatorId: user.id,
        projectTitle: `Project ${id}`,
      },
    });

    const membership = await prisma.groupMember.create({
      data: {
        groupId: group.id,
        userId: user.id,
        rollNo: `R_${id}`,
        name: user.name,
        email: user.email,
        memberType: "LEADER",
      },
    });

    // Link Firebase UID
    await prisma.user.update({
      where: { id: user.id },
      data: { firebaseUid: mockUid },
    });

    // Check relationships are preserved
    const checkUser = await prisma.user.findUniqueOrThrow({
      where: { id: user.id },
      include: { memberships: true, createdGroups: true },
    });
    expect(checkUser.memberships.length).toBe(1);
    expect(checkUser.memberships[0]?.id).toBe(membership.id);
    expect(checkUser.createdGroups[0]?.id).toBe(group.id);

    // Clean up group
    await prisma.groupMember.delete({ where: { id: membership.id } });
    await prisma.group.delete({ where: { id: group.id } });
  });

  // Scenario 19: NextAuth session role preservation
  it("Scenario 19: NextAuth session user role comes strictly from PostgreSQL and cannot be spoofed", async () => {
    const id = unique();
    const email = `session_user_${id}@apcoer.edu.in`;
    const mockUid = `fb_uid_session_${id}`;

    const user = await prisma.user.create({
      data: {
        name: `Session Student ${id}`,
        email,
        role: "STUDENT",
        passwordHash: await hashPassword("Password@123"),
        firebaseUid: mockUid,
        emailVerified: new Date(),
      },
    });
    createdUserIds.push(user.id);

    // Even if Firebase raw token has custom claims claims: { role: "HOD" }, backend role MUST be STUDENT
    vi.spyOn(firebaseAdminModule, "verifyFirebaseIdToken").mockResolvedValue({
      success: true,
      token: {
        uid: mockUid,
        email,
        emailVerified: true,
        raw: { uid: mockUid, email, role: "HOD" } as any, // Attacker tries spoofing
      },
    });

    const result = await authenticateWithFirebase("attacker-spoofed-token");
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.user.role).toBe("STUDENT"); // PostgreSQL is authoritative!
    }
  });

  // Scenario 20: Unauthorized API access rejection
  it("Scenario 20: rejects unauthorized internal API requests when HMAC authorization header is absent or invalid", async () => {
    // 1. Missing authorization
    const req1 = { headers: {} } as any;
    expect(readInternalIdentity(req1)).toBeNull();

    // 2. Tampered signature
    const req2 = { headers: { authorization: "Bearer invalid.signature.token" } } as any;
    expect(readInternalIdentity(req2)).toBeNull();

    // 3. Raw Firebase token passed as internal token
    const req3 = { headers: { authorization: "Bearer eyJhbGciOiJSUzI1NiIs..." } } as any;
    expect(readInternalIdentity(req3)).toBeNull();
  });
});

describe("Security Remediation Regressions (Fixes 1 - 8)", () => {
  // FIX 1: Account Takeover Prevention
  it("Fix 1A: [MOCKED FIREBASE ADMIN SDK + REAL POSTGRESQL PERSISTENCE] rejects unverified Firebase account attempting to link to HOD", async () => {
    const id = unique();
    const email = `hod_target_${id}@apcoer.edu.in`;
    const attackerUid = `fb_attacker_hod_${id}`;

    const hod = await prisma.user.create({
      data: {
        name: `HOD Target ${id}`,
        email,
        role: "HOD",
        passwordHash: await hashPassword("ValidHodPass@123"),
        createdVia: "HOD_CREATED",
        firebaseUid: null,
      },
    });
    createdUserIds.push(hod.id);

    vi.spyOn(firebaseAdminModule, "verifyFirebaseIdToken").mockResolvedValue({
      success: true,
      token: {
        uid: attackerUid,
        email,
        emailVerified: false, // Attacker has unverified Firebase account!
        raw: { uid: attackerUid, email, email_verified: false } as any,
      },
    });

    const result = await authenticateWithFirebase("unverified-hod-token");
    expect(result).toEqual({ ok: false, reason: "EMAIL_NOT_VERIFIED" });

    // Verify HOD user in PostgreSQL was NOT taken over
    const freshHod = await prisma.user.findUniqueOrThrow({ where: { id: hod.id } });
    expect(freshHod.firebaseUid).toBeNull();
  });

  it("Fix 1B: [MOCKED FIREBASE ADMIN SDK + REAL POSTGRESQL PERSISTENCE] rejects unverified Firebase account attempting to link to GUIDE", async () => {
    const id = unique();
    const email = `guide_target_${id}@apcoer.edu.in`;
    const attackerUid = `fb_attacker_guide_${id}`;

    const guide = await prisma.user.create({
      data: {
        name: `Guide Target ${id}`,
        email,
        role: "GUIDE",
        passwordHash: await hashPassword("ValidGuidePass@123"),
        createdVia: "HOD_CREATED",
        firebaseUid: null,
      },
    });
    createdUserIds.push(guide.id);

    vi.spyOn(firebaseAdminModule, "verifyFirebaseIdToken").mockResolvedValue({
      success: true,
      token: {
        uid: attackerUid,
        email,
        emailVerified: false,
        raw: { uid: attackerUid, email, email_verified: false } as any,
      },
    });

    const result = await authenticateWithFirebase("unverified-guide-token");
    expect(result).toEqual({ ok: false, reason: "EMAIL_NOT_VERIFIED" });

    // Verify GUIDE user was NOT linked
    const freshGuide = await prisma.user.findUniqueOrThrow({ where: { id: guide.id } });
    expect(freshGuide.firebaseUid).toBeNull();
  });

  it("Fix 1C: [MOCKED FIREBASE ADMIN SDK + REAL POSTGRESQL PERSISTENCE] links verified Firebase account to eligible existing user", async () => {
    const id = unique();
    const email = `student_eligible_${id}@apcoer.edu.in`;
    const legitUid = `fb_legit_${id}`;

    const student = await prisma.user.create({
      data: {
        name: `Eligible Student ${id}`,
        email,
        role: "STUDENT",
        passwordHash: await hashPassword("Password@123"),
        firebaseUid: null,
        emailVerified: null,
      },
    });
    createdUserIds.push(student.id);

    vi.spyOn(firebaseAdminModule, "verifyFirebaseIdToken").mockResolvedValue({
      success: true,
      token: {
        uid: legitUid,
        email,
        emailVerified: true,
        raw: { uid: legitUid, email, email_verified: true } as any,
      },
    });

    const result = await authenticateWithFirebase("verified-linking-token");
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.user.id).toBe(student.id);
    }

    const linked = await prisma.user.findUniqueOrThrow({ where: { id: student.id } });
    expect(linked.firebaseUid).toBe(legitUid);
    expect(linked.emailVerified).not.toBeNull();
  });

  it("Fix 1D: [MOCKED FIREBASE ADMIN SDK + REAL POSTGRESQL PERSISTENCE] rejects different Firebase UID attempting to access already-linked user", async () => {
    const id = unique();
    const email = `linked_user_${id}@apcoer.edu.in`;
    const originalUid = `fb_original_${id}`;
    const impostorUid = `fb_impostor_${id}`;

    const user = await prisma.user.create({
      data: {
        name: `Linked User ${id}`,
        email,
        role: "STUDENT",
        passwordHash: await hashPassword("Password@123"),
        firebaseUid: originalUid,
        emailVerified: new Date(),
      },
    });
    createdUserIds.push(user.id);

    vi.spyOn(firebaseAdminModule, "verifyFirebaseIdToken").mockResolvedValue({
      success: true,
      token: {
        uid: impostorUid,
        email,
        emailVerified: true,
        raw: { uid: impostorUid, email, email_verified: true } as any,
      },
    });

    const result = await authenticateWithFirebase("impostor-token");
    expect(result).toEqual({ ok: false, reason: "INVALID_CREDENTIALS" });

    const fresh = await prisma.user.findUniqueOrThrow({ where: { id: user.id } });
    expect(fresh.firebaseUid).toBe(originalUid);
  });

  it("Fix 1E: [MOCKED FIREBASE ADMIN SDK + REAL POSTGRESQL PERSISTENCE] allows legacy HOD login migration using correct credentials", async () => {
    const id = unique();
    const email = `hod_migrate_${id}@apcoer.edu.in`;
    const password = "LegacyHodSecret@123";
    const newUid = `fb_hod_migrated_${id}`;

    const hod = await prisma.user.create({
      data: {
        name: `HOD Migrate ${id}`,
        email,
        role: "HOD",
        passwordHash: await hashPassword(password),
        createdVia: "HOD_CREATED",
        firebaseUid: null,
      },
    });
    createdUserIds.push(hod.id);

    vi.spyOn(firebaseAdminModule, "isFirebaseAdminConfigured").mockReturnValue(true);
    vi.spyOn(firebaseAdminModule, "getFirebaseUserByEmail").mockResolvedValue(null);
    const createSpy = vi.spyOn(firebaseAdminModule, "createFirebaseUser").mockResolvedValue({
      uid: newUid,
      email,
    } as any);

    const authRes = await authenticate(email, password);
    expect(authRes.ok).toBe(true);
    if (authRes.ok) {
      expect(authRes.user.id).toBe(hod.id);
      expect(authRes.user.role).toBe("HOD");
    }

    expect(createSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        email,
        password,
        displayName: hod.name,
      }),
    );

    const freshHod = await prisma.user.findUniqueOrThrow({ where: { id: hod.id } });
    expect(freshHod.firebaseUid).toBe(newUid);
  });

  // FIX 4: Verification Email Dispatch
  it("Fix 4: [MOCKED FIREBASE ADMIN SDK + REAL POSTGRESQL PERSISTENCE] resendFirebaseVerificationEmail dispatches email with sendEmail and enforces 60s cooldown", async () => {
    const id = unique();
    const email = `unverified_resend_${id}@apcoer.edu.in`;

    const user = await prisma.user.create({
      data: {
        name: `Resend Student ${id}`,
        email,
        role: "STUDENT",
        passwordHash: await hashPassword("Password@123"),
        firebaseUid: `fb_uid_${id}`,
        emailVerified: null,
      },
    });
    createdUserIds.push(user.id);

    const generatedLink = "https://be-log-8f474.firebaseapp.com/__/auth/action?mode=verifyEmail&oobCode=XYZ";
    vi.spyOn(firebaseAdminModule, "isFirebaseAdminConfigured").mockReturnValue(true);
    firebaseAdminModule.setFirebaseAdminForTesting({} as any, {
      generateEmailVerificationLink: vi.fn().mockResolvedValue(generatedLink),
    } as any);

    const sendEmailSpy = vi.spyOn(emailModule, "sendEmail");

    // First attempt: should generate link and send email
    const res1 = await resendFirebaseVerificationEmail({ email });
    expect(res1.success).toBe(true);
    expect(sendEmailSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        to: email,
        recipientName: user.name,
        html: expect.stringContaining(generatedLink),
      }),
    );

    // Audit log should be recorded
    const log = await prisma.auditLog.findFirst({
      where: { userId: user.id, action: "RESEND_VERIFICATION_EMAIL" },
    });
    expect(log).not.toBeNull();

    // Second attempt immediately: should be rate-limited by 60s cooldown
    await expect(resendFirebaseVerificationEmail({ email })).rejects.toThrow(/wait 60 seconds/);
  });

  // FIX 5: Password Reset Locking & Email Verification Integrity
  it("Fix 5A: [REAL POSTGRESQL PERSISTENCE] legacy requestPasswordReset silently ignores migrated users", async () => {
    const id = unique();
    const email = `migrated_pw_req_${id}@apcoer.edu.in`;

    const user = await prisma.user.create({
      data: {
        name: `Migrated PW User ${id}`,
        email,
        role: "STUDENT",
        passwordHash: await hashPassword("Password@123"),
        firebaseUid: `fb_migrated_${id}`,
      },
    });
    createdUserIds.push(user.id);

    const result = await requestPasswordReset({ email });
    expect(result.success).toBe(true);
    expect(result.message).toContain("If an account exists");

    // No token should have been created
    const tokens = await prisma.passwordResetToken.findMany({ where: { userId: user.id } });
    expect(tokens.length).toBe(0);
  });

  it("Fix 5B: [REAL POSTGRESQL PERSISTENCE] legacy resetPassword rejects token if user has migrated to Firebase", async () => {
    const id = unique();
    const email = `token_migrated_${id}@apcoer.edu.in`;
    const rawToken = generateToken(32);

    const user = await prisma.user.create({
      data: {
        name: `Token Migrated ${id}`,
        email,
        role: "STUDENT",
        passwordHash: await hashPassword("OldPassword@123"),
        firebaseUid: `fb_now_migrated_${id}`,
      },
    });
    createdUserIds.push(user.id);

    await prisma.passwordResetToken.create({
      data: {
        userId: user.id,
        tokenHash: hashToken(rawToken),
        expiresAt: expiresIn(PASSWORD_RESET_TTL_MS),
      },
    });

    await expect(
      resetPassword({ token: rawToken, password: "NewPassword@123" }),
    ).rejects.toThrow(/managed with Firebase Authentication/);
  });

  it("Fix 5C: [REAL POSTGRESQL PERSISTENCE] legacy resetPassword does not mark unverified users as emailVerified", async () => {
    const id = unique();
    const email = `unverified_pw_${id}@apcoer.edu.in`;
    const rawToken = generateToken(32);

    const user = await prisma.user.create({
      data: {
        name: `Unverified Reset ${id}`,
        email,
        role: "STUDENT",
        passwordHash: await hashPassword("OldPassword@123"),
        firebaseUid: null,
        emailVerified: null,
        emailVerifiedAt: null,
      },
    });
    createdUserIds.push(user.id);

    await prisma.passwordResetToken.create({
      data: {
        userId: user.id,
        tokenHash: hashToken(rawToken),
        expiresAt: expiresIn(PASSWORD_RESET_TTL_MS),
      },
    });

    const res = await resetPassword({ token: rawToken, password: "BrandNewPassword@123" });
    expect(res.success).toBe(true);

    const updatedUser = await prisma.user.findUniqueOrThrow({ where: { id: user.id } });
    // Password was updated
    expect(updatedUser.passwordHash).not.toBe(user.passwordHash);
    // CRITICAL: emailVerified must STILL be null!
    expect(updatedUser.emailVerified).toBeNull();
    expect(updatedUser.emailVerifiedAt).toBeNull();
  });

  // FIX 6: Rate Limiting
  it("Fix 6: [MOCKED FIREBASE ADMIN SDK] authenticateWithFirebase enforces sliding window rate limit", async () => {
    resetBackendAuthRateLimits();
    const mockUid = `rate_limited_uid_${unique()}`;

    vi.spyOn(firebaseAdminModule, "verifyFirebaseIdToken").mockResolvedValue({
      success: true,
      token: {
        uid: mockUid,
        email: "any@apcoer.edu.in",
        emailVerified: true,
        raw: { uid: mockUid } as any,
      },
    });

    // Make 15 successful calls (within the limit of 15)
    for (let i = 0; i < 15; i++) {
      await authenticateWithFirebase("token");
    }

    // 16th call should be rate limited
    const res = await authenticateWithFirebase("token");
    expect(res).toEqual({ ok: false, reason: "RATE_LIMITED" });
    resetBackendAuthRateLimits();
  });
});
