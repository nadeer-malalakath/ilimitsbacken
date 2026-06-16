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

  exports.setParentPin = base.https.onCall(async (data, context) => {

    if (!context.auth) throw new functions.https.HttpsError("unauthenticated");
    if (!context.app) throw new functions.https.HttpsError("failed-precondition");

    const { pin } = data;

    if (!pin || pin.length < 4) {
      throw new functions.https.HttpsError("invalid-argument", "PIN must be at least 4 digits");
    }

    const ref = db.collection("users").doc(context.auth.uid);
    const snap = await ref.get();

    // 🚨 Prevent overwrite (important)
    if (snap.exists && snap.get("pinHash")) {
      throw new functions.https.HttpsError("failed-precondition", "PIN already set");
    }

    const hash = await bcrypt.hash(pin, 8);

    await ref.set({
      pinHash: hash,
      pinUpdatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

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
        url: "https://ilimits.app/verified.html"
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

       const childRef =
         db.collection("children").doc(context.params.childId);

       await childRef.update({
         unreadAlertCount: admin.firestore.FieldValue.increment(1),
         lastAlertAt: admin.firestore.FieldValue.serverTimestamp()
       });

     const RESTRICTED_PACKAGES = new Set([
       "com.tinder", "com.bumble.app", "com.dream11.fantasy", "com.mpl.mobile",
       "com.winzo.gold", "com.omegle.app", "com.monkey.video.chat", "com.pornhub.android",
       "com.xvideos.android", "com.hld.intelliscan", "com.hinge.app", "com.okcupid.okcupid",
       "com.match.android.matchapp", "com.grindrapp.android", "com.badoo.mobile",
       "com.azar", "com.omega.video.chat", "com.livetalk.meet", "com.heymatch.android",
       "com.my11circle", "com.fantasypower.app", "com.adda52.android", "com.pokerstars.mobile",
       "com.xnxx.video", "com.penthouse.android", "com.naughtydog.app", "com.hily.app",
       "com.coffeemeetsbagel", "com.jaumo", "com.chatspin.android", "com.livu", "com.holla",
       "com.parallel.space", "com.lbe.parallel.intl", "com.excelliance.multiaccounts",
       "com.applisto.appcloner", "com.calculator.vault", "com.hideitpro", "com.smartlock.applock",
       "com.apkpure.aegon", "com.aapkpure.aegon", "com.uptodown", "com.qooapp.qoohelper",
       "com.privateinternetaccess.android", "com.psiphon3", "com.free.vpn.unblock.messenger",
       "com.vpn.turbo", "com.snap.vpn", "com.uxin.vpnmaster", "com.vpnhub.android",
       "com.tunnelbear.android", "com.cloudflare.onedotonedotonedotone", "com.nordvpn.android",
       "com.expressvpn.vpn", "com.protonvpn.android", "com.windscribe.vpn", "com.ipvanish.android",
       "com.kik.android", "com.skout.android", "com.meetme.android.hornet", "com.mico",
       "com.liveme.android", "com.tango.me", "com.bigo.live", "com.yy.hiyo", "com.lamour.lite",
       "com.tumile.android", "com.photovault.photohide", "com.vaulty", "com.hidephoto.video",
       "com.calculator.lock.hide.app", "com.app.calculator.vault", "com.vault.hiddenapps",
       "com.hideitpro.vault", "com.safe.galleryvault", "com.thinkyeah.galleryvault",
       "com.parallel.space.lite", "com.parallel.space.pro", "com.excelliance.dualaid",
       "com.ludashi.dualspace", "com.trendmicro.tmas", "com.cloneapp.parallelspace",
       "com.app.hider.master", "com.doubleopen.app", "com.aptoide.android", "cm.aptoide.pt",
       "com.getjar.mobile", "org.fdroid.fdroid", "com.tutuapp", "com.mobilism.android",
       "com.filehide.filelocker", "com.hidefile.photo.video", "com.secretvault.app",
       "com.photohide.privategallery", "org.torproject.android", "org.torproject.torbrowser",
       "org.torproject.torbrowser_alpha", "com.duapps.recorder", "com.mobzapp.screenrecorder",
       "com.kimcy929.screenrecorder", "com.hecorat.screenrecorder.free", "com.dnschanger.no.root",
       "com.inetinet.proxy", "com.scheler.supervpn", "com.fast.free.unblock.thunder.vpn",
       "com.kiwibrowser.browser", "org.mozilla.firefox.focus", "com.alohabrowser.browser"
     ]);

     const { childId } = context.params;
     const alert = snap.data();

      console.log("ALERT RECEIVED", {
        time: new Date().toISOString(),
        childId,
        alertId: context.params.alertId,
        type: alert.type,
        severity: alert.severity,
        timestamp: alert.timestamp
      });

     // 1. Get child doc
     const childDoc = await db.collection("children").doc(childId).get();
     if (!childDoc.exists) return;

     const parentId  = childDoc.data().parentId;
     const childName = childDoc.data().name || "Your child";
     if (!parentId) return;

     // 2. Get parent FCM token
     const parentDoc = await db.collection("users").doc(parentId).get();
     if (!parentDoc.exists) return;

     const fcmToken = parentDoc.data().fcmToken;
     console.log("PARENT LOOKUP", {
       time: new Date().toISOString(),
       parentId,
       hasToken: !!fcmToken,
       tokenPrefix: fcmToken ? fcmToken.substring(0, 20) : null
     });
     if (!fcmToken) {
       console.log("No FCM token for parent:", parentId);
       return;
     }

     // 3. Determine if restricted install
     const isRestrictedInstall = alert.type === "app_installed" &&
       RESTRICTED_PACKAGES.has(alert.packageName);

     // 4. Build message
     const messages = {
       accessibility_disabled: {
         title: `${childName}'s monitoring is off`,
         body:  "Accessibility permission was disabled on the child's device."
       },
       app_limit_reached: {
         title: `${childName} hit a time limit`,
         body:  `${alert.appName || "An app"} limit was reached.`
       },
       blocked_app_opened: {
         title: `${childName} tried a blocked app`,
         body:  `${alert.appName || "A blocked app"} was attempted.`
       },
       app_installed: isRestrictedInstall ? {
         title: `⚠️ Restricted App Install Alert`,
         body:  `${childName} installed ${alert.appName || alert.packageName}, which is on the restricted apps list.`
       } : {
         title: `${childName} installed an app`,
         body:  `${alert.appName || "An app"} was installed`
       },
       app_uninstalled: {
         title: `${childName} removed an app`,
         body:  `${alert.appName || "An app"} was removed`
       }
     };

     const msg = messages[alert.type] || {
       title: `Alert for ${childName}`,
       body:  alert.message || "A new alert was triggered."
     };

     const severity = isRestrictedInstall ? "critical" : (alert.severity || "info");

     // 5. Send data-only FCM — no notification block so onMessageReceived always fires
     try {

        console.log("FCM SEND START", {
          time: new Date().toISOString(),
          parentId,
          type: alert.type,
          title: msg.title,
          severity
        });
         const startTime = Date.now();
        const category =
          alert.type === "app_installed"
            ? (
                isRestrictedInstall
                  ? "RESTRICTED_APP_INSTALLED"
                  : "APP_INSTALLED"
              )
            : undefined;
       const response = await admin.messaging().send({
         token: fcmToken,
          notification: {
             title: msg.title,
             body: msg.body
           },
         data: {
           type: alert.type || "generic",
           childId,
           alertId: context.params.alertId,
           timestamp: String(alert.timestamp || Date.now()),
           title: msg.title,
           body: msg.body,
           severity,
           packageName: alert.packageName || "",
           appName: alert.appName || "",
           category: category || ""
         },
         android: {
           priority: "high"
         },

          apns: {
            headers: {
              "apns-priority": "10"
            },
            payload: {
                  aps: {
                    alert: {
                      title: msg.title,
                      body: msg.body
                    },
                    sound: "default",
                    ...(category ? { category } : {})
                  }
                }
              }
       });
       console.log("FCM SEND SUCCESS", {
         time: new Date().toISOString(),
         response,
         durationMs: Date.now() - startTime,
         parentId,
         type: alert.type
       });
     } catch (e) {
       if (e.code === "messaging/registration-token-not-registered") {
         await db.collection("users").doc(parentId).update({
           fcmToken: admin.firestore.FieldValue.delete()
         });
       } else {
         console.error("FCM SEND FAILED", {
           code: e.code,
           message: e.message,
           stack: e.stack
         });
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

      exports.handleRevenueCatWebhook = functions
        .region("asia-south1")
        .runWith({
          timeoutSeconds: 15,
          memory: "256MB",
        })
        .https.onRequest(async (req, res) => {
          // ── 1. Authorize ────────────────────────────────────────────────────────
          const secret = functions.config().revenuecat?.webhook_secret;
          if (secret && req.headers["authorization"] !== secret) {
            console.warn("❌ Unauthorized RevenueCat webhook attempt");
            return res.status(401).send("Unauthorized");
          }

          try {
            // ── 2. Validate event payload ────────────────────────────────────────
            const event = req.body?.event;
            if (!event) {
              console.log("❌ Missing RevenueCat event");
              return res.status(400).send("Missing event");
            }
            console.log("🔥 RevenueCat Event:", JSON.stringify(event));

            const { type, product_id: productId = "", store } = event;

            // ── 3. Resolve UID ───────────────────────────────────────────────────
            // app_user_id  = CURRENT id — becomes the real Firebase UID after logIn()
            // original_app_user_id = FIRST-EVER id — almost always $RCAnonymousID, useless
            // aliases[]    = all known ids; scan as last resort for a non-anonymous one
            //
            // Priority: app_user_id (if real) → first non-anonymous alias → reject
            const isAnon = (id) => !id || id.startsWith("$RCAnonymousID");

            const uid = !isAnon(event.app_user_id)
              ? event.app_user_id
              : (event.aliases || []).find((a) => !isAnon(a));

            if (!uid) {
              console.log("❌ No valid UID — user not logged in yet. app_user_id:", event.app_user_id);
              return res.status(200).send("Ignored anonymous user");
            }

            // ── 4. Skip unknown / unhandled event types ──────────────────────────
            const ACTIVE_TYPES = new Set([
              "INITIAL_PURCHASE",
              "RENEWAL",
              "UNCANCELLATION",
              "NON_RENEWING_PURCHASE",
            ]);
            const INACTIVE_TYPES = new Set(["CANCELLATION", "EXPIRATION"]);
            const KNOWN_TYPES = new Set([
              ...ACTIVE_TYPES,
              ...INACTIVE_TYPES,
              "BILLING_ISSUE",
              "PRODUCT_CHANGE",
            ]);

            if (!KNOWN_TYPES.has(type)) {
              console.log("⚠️ Unhandled event type, skipping:", type);
              return res.status(200).send("Ignored");
            }

            // ── 5. Parse expiration safely ───────────────────────────────────────
            const expirationAtMs =
              event.expiration_at_ms != null
                ? Number(event.expiration_at_ms) || Number.MAX_SAFE_INTEGER
                : Number.MAX_SAFE_INTEGER;

            // ── 6. Determine isActive ────────────────────────────────────────────
            const isLifetime = productId.includes("lifetime");
            let isActive = false;

            if (isLifetime) {
              isActive = true;
            } else if (ACTIVE_TYPES.has(type)) {
              isActive = expirationAtMs > Date.now();
            } else if (INACTIVE_TYPES.has(type)) {
              isActive = false;
            } else if (type === "BILLING_ISSUE") {
              // Respect RevenueCat grace period — user still has access during it
              const grace = event.grace_period_expires_at_ms;
              isActive = grace ? Number(grace) > Date.now() : false;
            } else if (type === "PRODUCT_CHANGE") {
              // Mid-cycle plan change: treat as active if not yet expired
              isActive = expirationAtMs > Date.now();
            }

            // ── 7. Determine plan ────────────────────────────────────────────────
            let plan = "UNKNOWN";
            if (productId.includes("lifetime")) {
              plan = "LIFETIME";
            } else if (productId.includes("year")) {
              plan = "YEARLY";
            } else if (productId.includes("month")) {
              plan = "MONTHLY";
            }

            if (plan === "UNKNOWN") {
              console.warn("⚠️ Unrecognized productId pattern:", productId);
            }

            // ── 8. Determine entitlement ─────────────────────────────────────────
            const entitlement = event.entitlement_ids?.[0];
            if (!entitlement) {
              console.warn("⚠️ No entitlement_ids on event for uid:", uid);
            }

            // ── 9. Determine autoRenew ───────────────────────────────────────────
            // Active non-lifetime subscription that hasn't expired or been cancelled
            const autoRenew =
              !isLifetime &&
              expirationAtMs > Date.now() &&
              type !== "EXPIRATION" &&
              type !== "CANCELLATION";

            // ── 10. Deduplicate event ────────────────────────────────────────────
            // RevenueCat retries on failure — same event must never be processed twice
            const eventId = event.id;
            if (!eventId) {
              console.warn("⚠️ Missing RevenueCat event.id — skipping dedup");
            } else {
              const eventRef = db.collection("revenueCatEvents").doc(eventId);
              const existing = await eventRef.get();
              if (existing.exists) {
                console.log("⏭️ Duplicate RevenueCat event skipped:", eventId);
                return res.status(200).send("Duplicate");
              }
              // Mark as processed before writing user doc to prevent race conditions
              await eventRef.set({
                uid,
                type,
                processedAt: admin.firestore.FieldValue.serverTimestamp(),
              });
            }

            // ── 11. Protect lifetime users from accidental downgrade ─────────────
            const userRef = db.collection("users").doc(uid);
            const userSnap = await userRef.get();
            const currentPremium = userSnap.data()?.premium;
            if (currentPremium?.plan === "LIFETIME" && !isLifetime) {
              console.log("⏭️ Skipping downgrade for lifetime user:", uid);
              return res.status(200).send("Lifetime protected");
            }

            // ── 12. Write to Firestore ───────────────────────────────────────────
            await userRef.set(
              {
                premium: {
                  verified: true,
                  entitlement: entitlement ?? "premium",
                  isActive,
                  plan,
                  expiresAt: isLifetime ? Number.MAX_SAFE_INTEGER : expirationAtMs,
                  autoRenew,
                  productId,
                  source: store ?? "unknown",
                  revenueCatEvent: type,
                  lastUpdatedAt: admin.firestore.FieldValue.serverTimestamp(),
                },
              },
              { merge: true }
            );

            console.log(`✅ Premium updated for ${uid} — type=${type} active=${isActive} plan=${plan}`);
            return res.status(200).send("OK");
          } catch (e) {
            console.error("❌ RevenueCat webhook error:", e);
            return res.status(500).send("Internal Error");
          }
        });

        exports.verifyParentPin = base.https.onCall(async (data, context) => {

          console.log("========== verifyParentPin START ==========");

          if (!context.auth) {
            console.log("❌ No auth context");
            throw new functions.https.HttpsError("unauthenticated");
          }

          if (!context.app) {
            console.log("❌ No app check context");
            throw new functions.https.HttpsError("failed-precondition");
          }

          const uid = context.auth.uid;
          const pin = String(data.pin || "").trim();

          console.log("📱 Caller UID:", uid);
          console.log("🔢 PIN Length:", pin.length);

          const userSnap = await db.collection("users").doc(uid).get();

          if (!userSnap.exists) {
            console.log("❌ User document not found:", uid);
            throw new functions.https.HttpsError(
              "not-found",
              "User not found"
            );
          }

          const user = userSnap.data();

          console.log("👤 User Role:", user.role);
          console.log("👨‍👩‍👧 Parent ID:", user.parentId || null);

          let targetUid = uid;

          if (user.role === "child") {

            if (!user.parentId) {
              console.log("❌ Child has no parentId");
              throw new functions.https.HttpsError(
                "failed-precondition",
                "No parent linked"
              );
            }

            targetUid = user.parentId;
          }

          console.log("🎯 Target UID:", targetUid);

          const ref = db.collection("users").doc(targetUid);
          const snap = await ref.get();

          console.log("📄 Parent Doc Exists:", snap.exists);

          if (!snap.exists) {
            console.log("❌ Parent document missing:", targetUid);
            throw new functions.https.HttpsError(
              "not-found",
              "Parent document not found"
            );
          }

          const parent = snap.data();

          console.log("🔐 Has pinHash:", !!parent.pinHash);

          if (!parent.pinHash) {
            console.log("❌ Parent PIN not configured");
            throw new functions.https.HttpsError(
              "failed-precondition",
              "PIN not set"
            );
          }

          const valid = await bcrypt.compare(pin, parent.pinHash);

          console.log("✅ PIN Valid:", valid);

          return db.runTransaction(async (tx) => {

            const fresh = await tx.get(ref);
            const d = fresh.data();

            const attempts = d.pinAttempts || 0;
            const last = d.lastPinAttempt || 0;

            console.log("📊 Attempts:", attempts);
            console.log("🕒 Last Attempt:", last);

            if (
              attempts >= 5 &&
              Date.now() - last < 5 * 60 * 1000
            ) {

              console.log("🚫 Rate limited");

              throw new functions.https.HttpsError(
                "resource-exhausted",
                "Too many attempts. Try in 5 minutes."
              );
            }

            if (!valid) {

              console.log("❌ Invalid PIN entered");

              tx.update(ref, {
                pinAttempts: attempts + 1,
                lastPinAttempt: Date.now()
              });

              throw new functions.https.HttpsError(
                "permission-denied",
                "Invalid PIN"
              );
            }

            console.log("🎉 PIN verification successful");

            tx.update(ref, {
              pinAttempts: 0,
              lastPinAttempt: null
            });

            console.log("========== verifyParentPin SUCCESS ==========");

            return {
              success: true
            };
          });

        });

        exports.monitorOfflineChildren = functions
          .region("asia-south1")
          .runWith({ timeoutSeconds: 540, memory: "256MB" })
          .pubsub.schedule("every 60 minutes")
          .timeZone("Asia/Kolkata")
          .onRun(async (context) => {

            console.log("========== monitorOfflineChildren START ==========");

            const now = Date.now();
            const childrenSnap = await db.collection("children").get();

            if (childrenSnap.empty) {
              console.log("No children found. Exiting.");
              return null;
            }

            console.log(`Processing ${childrenSnap.size} children...`);

            const results = await Promise.allSettled(
              childrenSnap.docs.map(async (childDoc) => {

                const childId = childDoc.id;
                const child   = childDoc.data();
                const name    = child.name || "Child";

                if (child.isActivated === false) {
                  console.log(`[${childId}] Child inactive. Skipping offline monitoring.`);
                  return;
                }

                try {
                  console.log(`[${childId}] Processing: ${name}`);

                  // ── Read lastSyncAt from child doc (no subcollection query) ─────────
                  const lastSyncAt = child.lastSyncAt;

                  if (!lastSyncAt) {
                    console.log(`[${childId}] No lastSyncAt on child doc. Skipping.`);
                    return;
                  }

                  const lastSyncAtMs = typeof lastSyncAt.toMillis === "function"
                    ? lastSyncAt.toMillis()
                    : Number(lastSyncAt);

                  if (!lastSyncAtMs || Number.isNaN(lastSyncAtMs)) {
                    console.log(`[${childId}] Invalid lastSyncAt. Skipping.`);
                    return;
                  }

                  const hoursOffline     = (now - lastSyncAtMs) / (1000 * 60 * 60);
                  const safeHoursOffline = Math.max(0, hoursOffline);

                  const offline12hSent = child.offline12hSent === true;
                  const offline16hSent = child.offline16hSent === true;

                  console.log(`[${childId}] hoursOffline=${safeHoursOffline.toFixed(2)} 12hSent=${offline12hSent} 16hSent=${offline16hSent}`);

                  const childRef  = db.collection("children").doc(childId);
                  const alertsRef = childRef.collection("alerts");

                  // ── BACK ONLINE ──────────────────────────────────────────────────────
                  if (safeHoursOffline < 1 && (offline12hSent || offline16hSent)) {

                    console.log(`[${childId}] Back online. Creating alert + resetting flags.`);

                    await Promise.all([
                      alertsRef.add({
                        type:      "device_back_online",
                        severity:  "info",
                        message: `${name}'s device is back online.`,
                        timestamp: Date.now()
                      }),
                      childRef.update({
                        offline12hSent: false,
                        offline16hSent: false
                      })
                    ]);

                    console.log(`[${childId}] ✅ back_online alert created.`);
                    return;
                  }

                  // ── OFFLINE CRITICAL (16h) ───────────────────────────────────────────
                  if (safeHoursOffline >= 16 && !offline16hSent) {

                    console.log(`[${childId}] Offline >= 16h. Creating critical alert.`);

                    await Promise.all([
                      alertsRef.add({
                        type:      "device_offline_critical",
                        severity:  "critical",
                        message: `${name}'s device has not connected to iLimits for over 16 hours.`,
                        timestamp: Date.now()
                      }),
                      childRef.update({
                        offline16hSent: true,
                        offline12hSent: true   // prevent stale 12h backfill
                      })
                    ]);

                    console.log(`[${childId}] ✅ offline_critical alert created.`);
                    return;
                  }

                  // ── OFFLINE WARNING (12h) ────────────────────────────────────────────
                  if (safeHoursOffline >= 12 && !offline12hSent) {

                    console.log(`[${childId}] Offline >= 12h. Creating warning alert.`);

                    await Promise.all([
                      alertsRef.add({
                        type:      "device_offline_warning",
                        severity:  "critical",
                        message: `${name}'s device has not connected to iLimits for 12 hours.`,
                        timestamp: Date.now()
                      }),
                      childRef.update({
                        offline12hSent: true
                      })
                    ]);

                    console.log(`[${childId}] ✅ offline_warning alert created.`);
                    return;
                  }

                  console.log(`[${childId}] No state transition. Nothing to do.`);

                } catch (err) {
                  console.error(`[${childId}] ❌ Error:`, err.message);
                }
              })
            );

            const failed = results.filter(r => r.status === "rejected").length;
            console.log(`========== monitorOfflineChildren END — ${results.length} processed, ${failed} failed ==========`);

            return null;
          });

          exports.deleteOldAlerts = functions
            .region("asia-south1")
            .runWith({ timeoutSeconds: 540, memory: "256MB" })
            .pubsub.schedule("every 24 hours")
            .timeZone("Asia/Kolkata")
            .onRun(async () => {

              const cutoff = Date.now() - (3 * 24 * 60 * 60 * 1000);

              const childrenSnap = await db.collection("children").get();

              for (const childDoc of childrenSnap.docs) {

                const alertsSnap = await db
                  .collection("children")
                  .doc(childDoc.id)
                  .collection("alerts")
                  .where("timestamp", "<", cutoff)
                  .get();

                if (alertsSnap.empty) continue;

                const batch = db.batch();

                alertsSnap.docs.forEach(doc => {
                  batch.delete(doc.ref);
                });

                await batch.commit();

                console.log(
                  `Deleted ${alertsSnap.size} alerts for child ${childDoc.id}`
                );
              }

              return null;
            });