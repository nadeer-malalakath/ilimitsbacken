const functions = require("firebase-functions/v1");
const admin = require("firebase-admin");
const bcrypt = require("bcryptjs");

admin.initializeApp();
const db = admin.firestore();

// ─────────────────────────────────────────
// BASE CONFIG
// ─────────────────────────────────────────
const base = functions
  .region("asia-south1")
  .runWith({ timeoutSeconds: 10, memory: "256MB" });

// ─────────────────────────────────────────
// DELETE CHILD (SAFE + ATOMIC)
// ─────────────────────────────────────────
exports.deleteChildAccount = base.https.onCall(async (data, context) => {

  if (!context.auth) throw new functions.https.HttpsError("unauthenticated");
  if (!context.app) throw new functions.https.HttpsError("failed-precondition");

  const parentId = context.auth.uid;
  const { childId } = data;

  const childRef = db.collection("children").doc(childId);
  const snap = await childRef.get();

  if (!snap.exists) throw new functions.https.HttpsError("not-found");

  const child = snap.data();

  if (child.parentId !== parentId)
    throw new functions.https.HttpsError("permission-denied");

  try {
    await admin.auth().deleteUser(child.authUid);
  } catch (e) {
    if (e.code !== "auth/user-not-found") throw e;
  }

  const batch = db.batch();
  batch.delete(childRef);
  batch.update(db.collection("users").doc(parentId), {
    children: admin.firestore.FieldValue.arrayRemove(childId)
  });

  await batch.commit();

  await db.collection("auditLogs").add({
    action: "DELETE_CHILD",
    parentId,
    childId,
    ts: admin.firestore.FieldValue.serverTimestamp()
  });

  return { success: true };
});

// ─────────────────────────────────────────
// PIN MANAGEMENT
// ─────────────────────────────────────────
exports.setParentPin = base.https.onCall(async (data, context) => {

  if (!context.auth) throw new functions.https.HttpsError("unauthenticated");
  if (!context.app) throw new functions.https.HttpsError("failed-precondition");

  const uid = context.auth.uid;
  const pin = data.pin;

  if (!pin || pin.length < 4)
    throw new functions.https.HttpsError("invalid-argument");

  const ref = db.collection("users").doc(uid);
  const snap = await ref.get();

  if (snap.exists && snap.get("pinHash")) {
    throw new functions.https.HttpsError("failed-precondition", "PIN already set");
  }

  const hash = await bcrypt.hash(pin, 10);

  await ref.set({
    pinHash: hash,
    pinSetAt: admin.firestore.FieldValue.serverTimestamp()
  }, { merge: true });

  return { success: true };
});

// VERIFY PIN (OPTIMIZED)
exports.verifyParentPin = base.https.onCall(async (data, context) => {

  if (!context.auth) throw new functions.https.HttpsError("unauthenticated");
  if (!context.app) throw new functions.https.HttpsError("failed-precondition");

  const uid = context.auth.uid;
  const pin = data.pin;

  const ref = db.collection("users").doc(uid);
  const snap = await ref.get();

  if (!snap.exists) throw new functions.https.HttpsError("not-found");

  const user = snap.data();

  if (!user.pinHash) {
    throw new functions.https.HttpsError("failed-precondition", "PIN not set");
  }

  const valid = await bcrypt.compare(pin, user.pinHash);

  return db.runTransaction(async (tx) => {

    const fresh = await tx.get(ref);
    const data = fresh.data();

    const attempts = data.pinAttempts || 0;
    const last = data.lastPinAttempt || 0;

    if (attempts >= 5 && Date.now() - last < 5 * 60 * 1000) {
      throw new functions.https.HttpsError("resource-exhausted", "Try later");
    }

    if (!valid) {
      tx.update(ref, {
        pinAttempts: attempts + 1,
        lastPinAttempt: Date.now()
      });
      throw new functions.https.HttpsError("permission-denied", "Invalid PIN");
    }

    tx.update(ref, { pinAttempts: 0 });

    return { success: true };
  });
});

// CHANGE PIN
exports.changeParentPin = base.https.onCall(async (data, context) => {

  if (!context.auth) throw new functions.https.HttpsError("unauthenticated");
  if (!context.app) throw new functions.https.HttpsError("failed-precondition");

  const { oldPin, newPin } = data;

  const ref = db.collection("users").doc(context.auth.uid);
  const snap = await ref.get();

  if (!snap.exists || !snap.get("pinHash")) {
    throw new functions.https.HttpsError("failed-precondition");
  }

  const valid = await bcrypt.compare(oldPin, snap.get("pinHash"));

  if (!valid) {
    throw new functions.https.HttpsError("permission-denied");
  }

  const hash = await bcrypt.hash(newPin, 10);

  await ref.update({
    pinHash: hash,
    pinUpdatedAt: admin.firestore.FieldValue.serverTimestamp()
  });

  return { success: true };
});

// RESET PIN
exports.resetParentPin = base.https.onCall(async (data, context) => {

  if (!context.auth) throw new functions.https.HttpsError("unauthenticated");
  if (!context.app) throw new functions.https.HttpsError("failed-precondition");

  const { pin } = data;

  const authTime = context.auth.token.auth_time * 1000;

  if (Date.now() - authTime > 5 * 60 * 1000) {
    throw new functions.https.HttpsError("permission-denied", "Re-auth required");
  }

  const hash = await bcrypt.hash(pin, 10);

  await db.collection("users").doc(context.auth.uid).update({
    pinHash: hash,
    pinUpdatedAt: admin.firestore.FieldValue.serverTimestamp()
  });

  return { success: true };
});

// ─────────────────────────────────────────
// BIOMETRIC
// ─────────────────────────────────────────
exports.setBiometricPreference = base.https.onCall(async (data, context) => {

  if (!context.auth) throw new functions.https.HttpsError("unauthenticated");
  if (!context.app) throw new functions.https.HttpsError("failed-precondition");

  await db.collection("users").doc(context.auth.uid).set({
    biometricEnabled: data.enabled,
    biometricUpdatedAt: admin.firestore.FieldValue.serverTimestamp()
  }, { merge: true });

  return { success: true };
});

// ─────────────────────────────────────────
// FREE TIER (RESTORED)
// ─────────────────────────────────────────
const FREE_LIMITS = {
  blockedApps: 2,
  limitedApps: 2,
  categories: 1,
  children: 1,
};

async function getUsageDoc(parentId) {
  const ref = db.collection("users").doc(parentId)
    .collection("meta").doc("freeTierUsage");

  const snap = await ref.get();
  return { ref, data: snap.data() || {} };
}

async function isPremium(parentId) {
  const doc = await db.collection("users").doc(parentId).get();
  return doc.data()?.premium?.isActive === true;
}

exports.validateFreeTierAction = base.https.onCall(async (data, context) => {

  if (!context.auth) throw new functions.https.HttpsError("unauthenticated");
  if (!context.app) throw new functions.https.HttpsError("failed-precondition");

  const parentId = context.auth.uid;
  const { actionType, identifier } = data;

  if (await isPremium(parentId)) return { allowed: true };

  const { data: usage } = await getUsageDoc(parentId);

  switch (actionType) {

    case "block_app": {
      const blocked = usage.blockedApps || [];
      if (blocked.includes(identifier)) return { allowed: true };
      if (blocked.length >= FREE_LIMITS.blockedApps) {
        throw new functions.https.HttpsError("failed-precondition");
      }
      return { allowed: true };
    }

    case "set_app_limit": {
      const limited = usage.limitedApps || [];
      if (limited.includes(identifier)) return { allowed: true };
      if (limited.length >= FREE_LIMITS.limitedApps) {
        throw new functions.https.HttpsError("failed-precondition");
      }
      return { allowed: true };
    }

    case "create_category": {
      if ((usage.categoryCount || 0) >= FREE_LIMITS.categories) {
        throw new functions.https.HttpsError("failed-precondition");
      }
      return { allowed: true };
    }

    case "add_child": {
      if ((usage.childCount || 0) >= FREE_LIMITS.children) {
        throw new functions.https.HttpsError("failed-precondition");
      }
      return { allowed: true };
    }

    default:
      return { allowed: true };
  }
});

// ─────────────────────────────────────────
// SOFT BUFFER
// ─────────────────────────────────────────
exports.validateAndConsumeSoftBuffer = base.https.onCall(async (data, context) => {

  if (!context.auth) throw new functions.https.HttpsError("unauthenticated");
  if (!context.app) throw new functions.https.HttpsError("failed-precondition");

  const ref = db.collection("users")
    .doc(context.auth.uid)
    .collection("meta")
    .doc("freeTierUsage");

  const granted = await db.runTransaction(async (tx) => {

    const snap = await tx.get(ref);
    const used = snap.data()?.softBufferUsed || [];

    if (used.includes(data.bufferKey)) return false;

    tx.set(ref, {
      softBufferUsed: [...used, data.bufferKey],
      lastUpdated: Date.now()
    }, { merge: true });

    return true;
  });

  return { granted };
});

// ─────────────────────────────────────────
// RTDN (IDEMPOTENT)
// ─────────────────────────────────────────
exports.handlePlayRTDN = base.pubsub
  .topic("play-billing-topic")
  .onPublish(async (message) => {

    const data = message.json;
    const eventId = data?.eventId;

    if (!eventId) return;

    const logRef = db.collection("rtdnLogs").doc(eventId);
    if ((await logRef.get()).exists) return;

    await logRef.set({ processedAt: Date.now() });

    const sub = data?.subscriptionNotification;
    if (!sub) return;

    const uid = sub.obfuscatedExternalAccountId;
    if (!uid) return;

    const ref = db.collection("users").doc(uid);

    if ([1,2,4].includes(sub.notificationType)) {
      await ref.set({ premium: { isActive: true } }, { merge: true });
    }

    if ([12,13].includes(sub.notificationType)) {
      await ref.set({ premium: { isActive: false } }, { merge: true });
    }
  });