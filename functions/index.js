const functions = require("firebase-functions/v1");
const admin = require("firebase-admin");
const bcrypt = require("bcryptjs");
const { google } = require("googleapis");

admin.initializeApp();
const db = admin.firestore();

const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  host: "smtp.zoho.com",
  port: 465,
  secure: true,
  auth: {
    user: "support@ilimits.app",
    pass: "mc64 ycqL KMJh",
  },
});
// ─────────────────────────────────────────
// BASE CONFIG
// ─────────────────────────────────────────
const base = functions
  .region("asia-south1")
  .runWith({ timeoutSeconds: 10, memory: "256MB" });

// ─────────────────────────────────────────
// PLAY DEVELOPER API HELPER
// ─────────────────────────────────────────
async function getSubscriptionFromPlay(subscriptionId, purchaseToken) {
    const serviceAccount = JSON.parse(process.env.PLAY_SERVICE_ACCOUNT);

    const auth = new google.auth.GoogleAuth({
      credentials: serviceAccount,
      scopes: ["https://www.googleapis.com/auth/androidpublisher"],
    });
  const client = await auth.getClient();
  const androidPublisher = google.androidpublisher({ version: "v3", auth: client });

  const res = await androidPublisher.purchases.subscriptions.get({
    packageName: "com.timenest.app",
    subscriptionId: subscriptionId,
    token: purchaseToken
  });

  return res.data;
}

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
    await admin.auth().deleteUser(child.uid);
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
exports.verifyParentPin = base.https.onCall(async (data, context) => {

  if (!context.auth) throw new functions.https.HttpsError("unauthenticated");
  if (!context.app) throw new functions.https.HttpsError("failed-precondition");

  const uid = context.auth.uid;
  const pin = data.pin;

  // 🔹 Step 1: get current user
  const userSnap = await db.collection("users").doc(uid).get();
  if (!userSnap.exists) {
    throw new functions.https.HttpsError("not-found");
  }

  const user = userSnap.data();

  // 🔹 Step 2: resolve parent
  let targetUid = uid;

  if (user.role === "child") {
    if (!user.parentId) {
      throw new functions.https.HttpsError("failed-precondition", "No parent linked");
    }
    targetUid = user.parentId;
  }

  const ref = db.collection("users").doc(targetUid);

  const snap = await ref.get();
  if (!snap.exists) throw new functions.https.HttpsError("not-found");

  const parent = snap.data();

  if (!parent.pinHash) {
    throw new functions.https.HttpsError("failed-precondition", "PIN not set");
  }

  const valid = await bcrypt.compare(pin, parent.pinHash);

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

// ─────────────────────────────────────────
// CHANGE PIN — fixed
// ─────────────────────────────────────────
//
// Changes from original:
//   1. bcrypt rounds reduced 10 → 8  (cold start was pushing past timeout)
//   2. Explicit INTERNAL error logging so you can see failures in Functions logs
//   3. Verify the old PIN inside a transaction so reads are consistent
//   4. Increased timeout to 15s to cover worst-case cold starts
//
exports.changeParentPin = functions
  .region("asia-south1")
  .runWith({ timeoutSeconds: 15, memory: "256MB" })  // ← was 10s
  .https.onCall(async (data, context) => {

    if (!context.auth) throw new functions.https.HttpsError("unauthenticated");
    if (!context.app)  throw new functions.https.HttpsError("failed-precondition");

    const { oldPin, newPin } = data;

    if (!oldPin || oldPin.length < 4)
      throw new functions.https.HttpsError("invalid-argument", "Old PIN too short");

    if (!newPin || newPin.length < 4)
      throw new functions.https.HttpsError("invalid-argument", "New PIN too short");

    const ref = db.collection("users").doc(context.auth.uid);
    const snap = await ref.get();

    if (!snap.exists || !snap.get("pinHash")) {
      throw new functions.https.HttpsError("failed-precondition", "No PIN set");
    }

    // ── Verify old PIN ────────────────────────────────────────────────────
    let valid;
    try {
      valid = await bcrypt.compare(oldPin, snap.get("pinHash"));
    } catch (e) {
      console.error("bcrypt.compare failed:", e);
      throw new functions.https.HttpsError("internal", "Verification failed");
    }

    if (!valid) {
      throw new functions.https.HttpsError("permission-denied", "Incorrect PIN");
    }

    // ── Hash new PIN ──────────────────────────────────────────────────────
    let hash;
    try {
      hash = await bcrypt.hash(newPin, 8);  // ← was 10, reduced to avoid timeout
    } catch (e) {
      console.error("bcrypt.hash failed:", e);
      throw new functions.https.HttpsError("internal", "Failed to hash PIN");
    }

    // ── Persist ───────────────────────────────────────────────────────────
    try {
      await ref.update({
        pinHash: hash,
        pinUpdatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
    } catch (e) {
      console.error("Firestore update failed:", e);
      throw new functions.https.HttpsError("internal", "Failed to save PIN");
    }

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
  const premium = doc.data()?.premium;
// In isPremium(), add a log:
  if (!premium) return false;
  if (premium.plan === "LIFETIME") {
   return true; // 🔥 Lifetime = always premium
  }

  console.log("premium doc:", JSON.stringify(premium));
  console.log("expiresAt type:", typeof premium.expiresAt, "value:", premium.expiresAt);

    const expiresAt = Number(premium.expiresAt ?? -1);
    if (expiresAt < 0) return false;   // ✅ never subscribed / sentinel
    return (
        premium.isActive === true &&
        expiresAt > Date.now()
    );
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
exports.handlePlayRTDN = functions
  .region("asia-south1")
  .runWith({
    timeoutSeconds: 10,
    memory: "256MB",
    secrets: ["PLAY_SERVICE_ACCOUNT"],
  })
  .pubsub
  .topic("play-billing-topic")
  .onPublish(async (message) => {

    console.log("STEP 1: FULL RTDN =", JSON.stringify(message.json));

    const data = message.json;
    const sub  = data?.subscriptionNotification;

    if (!sub) {
      console.log("STEP 2: ❌ Not a subscription event. Keys:", Object.keys(data));
      return;
    }

    console.log("STEP 3: ✅ subscriptionNotification received");
    console.log("STEP 4: purchaseToken =", sub.purchaseToken);

    // ── Dedupe by Pub/Sub message ID ─────────────────────────────────
    const dedupeKey = `${sub.purchaseToken}_${sub.notificationType}_${data.eventTimeMillis}`;
    const logRef    = db.collection("rtdnLogs").doc(dedupeKey);

    if ((await logRef.get()).exists) {
      console.log("Duplicate event skipped:", dedupeKey);
      return;
    }

    await logRef.set({ processedAt: Date.now() });
    console.log("✅ STEP 5: Dedupe passed, processing event");

    // ── Resolve UID from purchaseTokens ──────────────────────────────
    console.log("STEP 6: Looking up purchaseToken in Firestore...");
    let tokenDoc;
    let attempts = 0;

    while (attempts < 5) {
      tokenDoc = await db.collection("purchaseTokens").doc(sub.purchaseToken).get();
      console.log(`STEP 6 attempt ${attempts + 1}: tokenDoc.exists =`, tokenDoc.exists);
      if (tokenDoc.exists) break;
      await new Promise(r => setTimeout(r, 1000));
      attempts++;
    }

    if (!tokenDoc.exists) {
      console.log("⚠️ STEP 7: Token not found after retries, trying Play API fallback");

      try {
        const subscriptionData = await getSubscriptionFromPlay(
          sub.subscriptionId,
          sub.purchaseToken
        );

        console.log("STEP 7b: Play API raw UID =", subscriptionData.obfuscatedExternalAccountId);

        const uid = subscriptionData.obfuscatedExternalAccountId;

        if (!uid || typeof uid !== "string") {
          console.log("❌ STEP 7c: UID missing or invalid from Play API, cannot recover");
          return;
        }

        console.log("✅ STEP 7d: UID recovered from Play API:", uid);

        const expiryMs = Number(subscriptionData.expiryTimeMillis ?? 0);
        const now = Date.now();

        await db.collection("users").doc(uid).set({
          premium: {
            isActive: expiryMs > now,
            expiresAt: expiryMs,
            autoRenew: subscriptionData.autoRenewing === true,
            plan: sub.subscriptionId.includes("year")
              ? "YEARLY"
              : sub.subscriptionId.includes("month")
              ? "MONTHLY"
              : "UNKNOWN",
            source: "play_store_fallback",
            verified: true,
            lastUpdatedAt: admin.firestore.FieldValue.serverTimestamp()
          }
        }, { merge: true });

        console.log("✅ STEP 7e: Firestore updated via Play API fallback for uid:", uid);

      } catch (e) {
        console.error("❌ STEP 7 Play API fallback failed:", e.message, e.code || "");
      }

      return;
    }

    const uid = tokenDoc.data().uid;

    if (!uid) {
      console.log("❌ STEP 8: UID missing in purchaseTokens doc");
      return;
    }

    console.log("✅ STEP 8: Token found, uid =", uid);

    const ref       = db.collection("users").doc(uid);
    const type      = sub.notificationType;
    const eventTime = Number(data.eventTimeMillis) || Date.now();
    const eventId   = `${sub.purchaseToken}_${data.eventTimeMillis}`;;
    const now       = Date.now();

    const ACTIVE_TYPES   = [1, 4, 7, 13];
    const CANCELED_TYPES = [3];
    const EXPIRED_TYPES  = [2];
    const PAUSED_TYPES   = [10];
    const ON_HOLD_TYPES  = [5];
    const REVOKED_TYPES  = [12];

    // ── Identity fields included in every branch ──────────────────────
    const identity = {
      purchaseToken:  sub.purchaseToken,
      subscriptionId: sub.subscriptionId,
      productId:      sub.subscriptionId,
      source:         "play_store",
      lastEventType:  type,
      lastEventId:    eventId,
    };

    // ── Extract verified fields from Play API response ─────────────────
    function extractPlayFields(s) {
      const expiresAt = Number(s.expiryTimeMillis) || -1;
      const isActive = expiresAt > now;
      const autoRenew = s.autoRenewing === true || (expiresAt > now);
      const orderId      = s.orderId      || null;
      const linkedToken  = s.linkedPurchaseToken || null;
      const acknowledged = s.acknowledgementState === 1;
      const regionCode   = s.regionCode   || null;
      const basePlanId   = s.lineItems?.[0]?.offerDetails?.basePlanId || null;
      const offerId      = s.lineItems?.[0]?.offerDetails?.offerId    || null;
      const plan         = sub.subscriptionId.includes("year")
        ? "YEARLY"
        : sub.subscriptionId.includes("month")
        ? "MONTHLY"
        : "UNKNOWN";

      return {
        expiresAt,
        isActive,
        autoRenew,
        orderId,
        linkedPurchaseToken: linkedToken,
        acknowledged,
        regionCode,
        basePlanId,
        offerId,
        plan,
        verifiedAt: admin.firestore.FieldValue.serverTimestamp(),
      };
    }

    // ── Transactional write with duplicate + stale guard ──────────────
    async function txWrite(ref, payload) {
      let skipped = false;

      await db.runTransaction(async (tx) => {
        const snap           = await tx.get(ref);
        const current        = snap.data()?.premium || {};
        const currentUpdated = current.lastUpdatedAt?.toMillis?.() || 0;

        if (current.plan === "LIFETIME") {
            console.log("⏭️ Skipping update — user already lifetime");
            skipped = true;
            return;
        }

        if (current.lastEventId === eventId) {
          console.log("⏭️ Duplicate event skipped", { eventId });
          skipped = true;
          return;
        }

        if (currentUpdated && eventTime < currentUpdated) {
          console.log("⏭️ Stale event skipped", { eventTime, currentUpdated });
          skipped = true;
          return;
        }

        tx.set(ref, {
          premium: {
            ...payload,
            lastUpdatedAt: admin.firestore.FieldValue.serverTimestamp()
          }
        }, { merge: true });
      });

      return skipped;
    }

    // ── Build payload per branch ──────────────────────────────────────
    let payload = { ...identity };

    if (ACTIVE_TYPES.includes(type)) {
      try {
        const s = await getSubscriptionFromPlay(sub.subscriptionId, sub.purchaseToken);
        const f = extractPlayFields(s);

        payload = {
          ...payload,
          ...f,
          verified: true,
          onHold:   false,
          paused:   false,
        };
      } catch (e) {
        console.error("❌ Play API ERROR on active:", JSON.stringify(e, null, 2));
        return;
      }

    } else if (CANCELED_TYPES.includes(type)) {
      try {
        const s = await getSubscriptionFromPlay(sub.subscriptionId, sub.purchaseToken);
        const f = extractPlayFields(s);

        payload = {
          ...payload,
          ...f,
          canceledAt: admin.firestore.FieldValue.serverTimestamp(),
        };
      } catch (e) {
        console.error("❌ Play API ERROR on cancel:", JSON.stringify(e, null, 2));
        return;
      }

    } else if (EXPIRED_TYPES.includes(type)) {
      try {
        const s = await getSubscriptionFromPlay(sub.subscriptionId, sub.purchaseToken);
        const f = extractPlayFields(s);

        payload = {
          ...payload,
          isActive:  f.isActive,
          expiresAt: f.expiresAt,
          autoRenew: false,
          onHold:    false,
          paused:    false,
        };
      } catch (e) {
        console.error("❌ Play API ERROR on expire", {
          message: e.message,
          code: e.code,
          token: sub.purchaseToken,
        });
        payload = {
          ...payload,
          isActive:  false,
          expiresAt: -1,
          autoRenew: false,
          onHold:    false,
          paused:    false,
        };
      }

    } else if (PAUSED_TYPES.includes(type)) {
      try {
        const s = await getSubscriptionFromPlay(sub.subscriptionId, sub.purchaseToken);
        const f = extractPlayFields(s);

        payload = {
          ...payload,
          ...f,
          paused:  true,
          onHold:  false,
        };
      } catch (e) {
        console.error("❌ Play API ERROR on pause:", JSON.stringify(e, null, 2));
        return;
      }

    } else if (ON_HOLD_TYPES.includes(type)) {
      try {
        const s = await getSubscriptionFromPlay(sub.subscriptionId, sub.purchaseToken);
        const f = extractPlayFields(s);

        payload = {
          ...payload,
          ...f,
          onHold: true,
          paused: false,
        };
      } catch (e) {
        console.error("❌ Play API ERROR on hold:", JSON.stringify(e, null, 2));
        return;
      }

    } else if (REVOKED_TYPES.includes(type)) {
      payload = {
        ...payload,
        isActive:  false,
        expiresAt: -1,
        autoRenew: false,
        onHold:    false,
        paused:    false,
      };

    } else {
      console.warn("⚠️ Unhandled RTDN", { type, sub, eventId });
      return;
    }

    // ── Single transactional write for all branches ───────────────────
    const skipped = await txWrite(ref, payload);
    if (skipped) return;
    console.log("✅ STEP 9: Firestore updated for uid:", uid, "type:", type);
    })

  exports.sendCustomVerificationEmail = base.https.onCall(async (data, context) => {

    console.log("FUNCTION HIT 🔥");

    const { email, name } = data;

    if (!email)
      throw new functions.https.HttpsError("invalid-argument");

    try {
      // 🔥 Generate Firebase verification link
      const link = await admin.auth().generateEmailVerificationLink(email, {
        url: "https://ilimits.app/verified"
      });

      // ✨ Premium email template
      const html = `
        <div style="font-family:sans-serif;padding:20px">
          <h2 style="color:#4CAF50">Welcome to iLimits 👋</h2>
          <p>Hi ${name || "User"},</p>
          <p>Please verify your email to continue:</p>

          <a href="${link}"
             style="display:inline-block;padding:12px 20px;
                    background:#4CAF50;color:white;
                    text-decoration:none;border-radius:6px;">
            Verify Email
          </a>

          <p style="margin-top:20px;font-size:12px;color:gray">
            If you didn't request this, ignore this email.
          </p>
        </div>
      `;

      await transporter.sendMail({
        from: "iLimits <support@ilimits.app>",
        to: email,
        subject: "Verify your email",
        html,
      });

      return { success: true };

    } catch (e) {
        console.error("EMAIL FULL ERROR:", e);
        throw new functions.https.HttpsError("internal", e.message);
      }
  });

  // ─────────────────────────────────────────
  // VERIFY AND RESTORE SUBSCRIPTION
  // ─────────────────────────────────────────
  exports.verifyAndRestoreSubscription = functions
    .region("asia-south1")
    .runWith({ timeoutSeconds: 15, memory: "256MB", secrets: ["PLAY_SERVICE_ACCOUNT"] })
    .https.onCall(async (data, context) => {

      if (!context.auth) throw new functions.https.HttpsError("unauthenticated");
      if (!context.app)  throw new functions.https.HttpsError("failed-precondition");

      const uid          = context.auth.uid;
      const { purchaseToken, productId } = data;

      if (!purchaseToken || !productId) {
        throw new functions.https.HttpsError("invalid-argument", "Missing purchaseToken or productId");
      }

      const isLifetime = productId === "ilimits_premium_lifetime";

      // ── Lifetime INAPP — no expiry check needed ───────────────────────────────
      // ── Lifetime INAPP — no expiry check needed ───────────────────────────────
      if (isLifetime) {

        const tokenRef = db.collection("purchaseTokens").doc(purchaseToken);
        const tokenSnap = await tokenRef.get();

        // 🛑 If token already exists → check ownership
        if (tokenSnap.exists) {
          const existingUid = tokenSnap.data().uid;
          if (existingUid !== uid) {
            console.log("❌ Token belongs to another user:", existingUid);
            return { isActive: false, isExpired: true, error: "PURCHASE_ALREADY_USED" };
          }
        }

        // ✅ NEW: Verify ownership via Play API (catches first-time restores where
        //         no purchaseTokens doc exists yet)
        try {
          const serviceAccount = JSON.parse(process.env.PLAY_SERVICE_ACCOUNT);
          const auth = new google.auth.GoogleAuth({
            credentials: serviceAccount,
            scopes: ["https://www.googleapis.com/auth/androidpublisher"],
          });
          const client = await auth.getClient();
          const androidPublisher = google.androidpublisher({ version: "v3", auth: client });

          const productPurchase = await androidPublisher.purchases.products.get({
            packageName: "com.timenest.app",
            productId: "ilimits_premium_lifetime",
            token: purchaseToken
          });

          const obfuscatedUid = productPurchase.data.obfuscatedExternalAccountId;

          if (obfuscatedUid && obfuscatedUid !== uid) {
            console.log("❌ INAPP token belongs to:", obfuscatedUid, "not:", uid);
            return { isActive: false, isExpired: true, error: "PURCHASE_ALREADY_USED" };
          }

          // ⚠️ If obfuscatedUid is missing AND no tokenSnap — reject, can't prove ownership
          if (!obfuscatedUid && !tokenSnap.exists) {
            console.log("❌ Cannot verify lifetime ownership — no obfuscatedUid and no token doc");
            return { isActive: false, isExpired: true, error: "PURCHASE_ALREADY_USED" };
          }

        } catch (e) {
          // If Play API call fails, fall back to tokenSnap check only
          // If tokenSnap also doesn't exist, we can't verify — reject
          if (!tokenSnap.exists) {
            console.error("❌ Play API failed and no token doc — cannot verify:", e.message);
            return { isActive: false, isExpired: true, error: "PURCHASE_ALREADY_USED" };
          }
          console.warn("⚠️ Play API check failed, proceeding with tokenSnap only:", e.message);
        }

        // ✅ Save mapping (first-time restore or purchase)
        await tokenRef.set({
          uid,
          createdAt: admin.firestore.FieldValue.serverTimestamp()
        }, { merge: true });

        // ✅ Grant premium
        await db.collection("users").doc(uid).set({
          premium: {
            isActive: true,
            plan: "LIFETIME",
            expiresAt: Number.MAX_SAFE_INTEGER,
            source: "play_store",
            lastUpdatedAt: admin.firestore.FieldValue.serverTimestamp()
          }
        }, { merge: true });

        return { isActive: true, isExpired: false, plan: "LIFETIME" };
      }

      // ── Subscription — verify with Play API ───────────────────────────────────
      let subscriptionData;
      try {
        subscriptionData = await getSubscriptionFromPlay(productId, purchaseToken);
      } catch (e) {
        console.error("Play API error during restore:", e.message);
        throw new functions.https.HttpsError("internal", "Unable to verify with Play Store");
      }

      // ✅ ADD THIS: Check token ownership before granting premium
      const obfuscatedUid = subscriptionData.obfuscatedExternalAccountId;
      const tokenRef = db.collection("purchaseTokens").doc(purchaseToken);
      const tokenSnap = await tokenRef.get();

      if (tokenSnap.exists) {
        const existingUid = tokenSnap.data().uid;
        if (existingUid !== uid) {
          console.log("❌ Token belongs to another user:", existingUid);
          return { isActive: false, isExpired: true, error: "PURCHASE_ALREADY_USED" };
        }
      }



      // Also cross-check with Play API's obfuscatedExternalAccountId
      if (obfuscatedUid && obfuscatedUid !== uid) {
        console.log("❌ Play API UID mismatch:", obfuscatedUid, "vs", uid);
        return { isActive: false, isExpired: true, error: "PURCHASE_ALREADY_USED" };
      }

      if (!tokenSnap.exists && !obfuscatedUid) {
                console.log("❌ Invalid restore — no ownership proof");

                return {
                  isActive: false,
                  isExpired: true,
                  error: "INVALID_RESTORE"
                };
              }

      const expiryMs  = Number(subscriptionData.expiryTimeMillis ?? 0);
      const now       = Date.now();
      const isActive  = expiryMs > now && subscriptionData.paymentState !== 0;
      const isExpired = !isActive;

      const plan = productId.includes("year") ? "YEARLY"
                 : productId.includes("month") ? "MONTHLY"
                 : "UNKNOWN";

      console.log(`Restore check — uid:${uid} plan:${plan} expiryMs:${expiryMs} now:${now} isActive:${isActive}`);

      if (isActive) {
        // ── Active — restore premium ──────────────────────────────────────────
        await db.collection("users").doc(uid).set({
          premium: {
            isActive:      true,
            plan,
            expiresAt:     expiryMs,
            autoRenew:     subscriptionData.autoRenewing === true,
            source:        "play_store",
            verified:      true,
            lastUpdatedAt: admin.firestore.FieldValue.serverTimestamp()
          }
        }, { merge: true });

        // Save token mapping so RTDN webhooks can find this user
        await db.collection("purchaseTokens").doc(purchaseToken).set({
          uid,
          createdAt: admin.firestore.FieldValue.serverTimestamp()
        });

      } else {
        // ── Expired — clear premium ───────────────────────────────────────────
        await db.collection("users").doc(uid).set({
          premium: {
            isActive:      false,
            plan:          "FREE",
            expiresAt:     expiryMs > 0 ? expiryMs : -1,
            lastUpdatedAt: admin.firestore.FieldValue.serverTimestamp()
          }
        }, { merge: true });
      }

      return { isActive, isExpired, plan, expiresAt: expiryMs };
    });

    exports.notifyParentOnAlert = functions
      .region("asia-south1")
      .firestore
      .document("children/{childId}/alerts/{alertId}")
      .onCreate(async (snap, context) => {
        const { childId } = context.params;
        const alert = snap.data();

        // 1. Get the child doc to find parentId
        const childDoc = await db.collection("children").doc(childId).get();
        if (!childDoc.exists) return;

        const parentId = childDoc.data().parentId;
        const childName = childDoc.data().name || "Your child";
        if (!parentId) return;

        // 2. Get parent's FCM token
        const parentDoc = await db.collection("users").doc(parentId).get();
        if (!parentDoc.exists) return;

        const fcmToken = parentDoc.data().fcmToken;
        if (!fcmToken) {
          console.log("No FCM token for parent:", parentId);
          return;
        }

        // 3. Build the message based on alert type
        const messages = {
          accessibility_disabled: {
            title: `${childName}'s monitoring is off`,
            body: "Accessibility permission was disabled on the child's device."
          },
          app_limit_reached: {
            title: `${childName} hit a time limit`,
            body: `${alert.appName || "An app"} limit was reached.`
          },
          blocked_app_opened: {
            title: `${childName} tried a blocked app`,
            body: `${alert.appName || "A blocked app"} was attempted.`
          }
        };

        const msg = messages[alert.type] || {
          title: `Alert for ${childName}`,
          body: alert.message || "A new alert was triggered."
        };

        // 4. Send via FCM
        try {
          await admin.messaging().send({
            token: fcmToken,
            notification: {
              title: msg.title,
              body: msg.body
            },
            data: {
              type: alert.type || "generic",
              childId,
              alertId: context.params.alertId,
              timestamp: String(alert.timestamp || Date.now())
            },
            android: {
              priority: "high",
              notification: {
                channelId: "my_channel_id",  // matches NOTIFICATION_CHANNEL_ID in your service
                sound: "default"
              }
            }
          });
          console.log("Parent notified:", parentId, "for alert type:", alert.type);
        } catch (e) {
          if (e.code === "messaging/registration-token-not-registered") {
            // Token is stale — clear it so we don't retry
            await db.collection("users").doc(parentId).update({ fcmToken: admin.firestore.FieldValue.delete() });
          } else {
            console.error("FCM send failed:", e.message);
          }
        }
      });

      exports.initializeTrial = functions
          .region("asia-south1")
          .https.onCall(async (data, context) => {
          const uid = context.auth?.uid;

          if (!uid) {
              throw new functions.https.HttpsError(
                  "unauthenticated",
                  "User must be authenticated"
              );
          }

          const userRef = admin.firestore().collection("users").doc(uid);
          const doc = await userRef.get();

          // Prevent overwrite (VERY IMPORTANT)
          if (doc.exists && doc.data().trialStart) {
              return { status: "already_initialized" };
          }

          const now = admin.firestore.Timestamp.now();

          const trialDurationMs = 5 * 24 * 60 * 60 * 1000;
          const trialEnd = admin.firestore.Timestamp.fromMillis(
              now.toMillis() + trialDurationMs
          );

          await userRef.set(
              {
                  trialStart: now,
                  trialEnd: trialEnd
              },
              { merge: true }
          );

          return { status: "initialized" };
      });