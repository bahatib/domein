const DATABASE = "domein-response-archive";
const VERSION = 1;
const STORE = "responses";
let dbPromise;
let archiveNotifyTimer = null;

function notifyArchiveChanged() {
  if (archiveNotifyTimer) clearTimeout(archiveNotifyTimer);
  archiveNotifyTimer = setTimeout(() => {
    archiveNotifyTimer = null;
    try { chrome.runtime.sendMessage({ type: "domein-archive-updated" }).catch(() => {}); } catch {}
  }, 250);
}

function openDatabase() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE, VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE)) {
        const store = db.createObjectStore(STORE, { keyPath: "id", autoIncrement: true });
        store.createIndex("byRoot", "root");
        store.createIndex("byTimestamp", "timestamp");
        store.createIndex("byUrl", "url");
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => { dbPromise = null; reject(request.error || new Error("Could not open the local response archive.")); };
    request.onblocked = () => { dbPromise = null; reject(new Error("The local response archive is blocked by another browser tab.")); };
  });
  return dbPromise;
}

export async function archiveResponse(response, { root, scanId, requestedUrl }) {
  const copy = response.clone();
  const body = await copy.blob();
  const headers = Object.fromEntries(copy.headers.entries());
  const record = {
    root,
    scanId,
    timestamp: new Date().toISOString(),
    requestedUrl,
    url: copy.url || requestedUrl,
    status: copy.status,
    statusText: copy.statusText,
    ok: copy.ok,
    redirected: copy.redirected,
    type: copy.type,
    headers,
    contentType: copy.headers.get("content-type") || "",
    body,
    bodyBytes: body.size
  };
  const db = await openDatabase();
  await new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).add(record);
    tx.onerror = () => reject(tx.error || new Error("Could not save the response locally."));
    tx.onabort = () => reject(tx.error || new Error("Saving the response archive was interrupted."));
    tx.oncomplete = () => { resolve(); notifyArchiveChanged(); };
  });
}

export async function getArchivedResponseCount() {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const request = db.transaction(STORE, "readonly").objectStore(STORE).count();
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function publicMetadata({ body, ...metadata }) { return metadata; }

export async function listArchivedResponses(query = "", limit = 100) {
  const db = await openDatabase();
  const needle = query.trim().toLowerCase();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readonly");
    const request = tx.objectStore(STORE).index("byTimestamp").openCursor(null, "prev");
    const rows = [];
    request.onsuccess = () => {
      const cursor = request.result;
      if (!cursor || rows.length >= limit) { resolve(rows); return; }
      const record = cursor.value;
      const searchable = `${record.root} ${record.requestedUrl} ${record.url} ${record.contentType} ${record.status} ${record.scanId}`.toLowerCase();
      if (!needle || searchable.includes(needle)) rows.push(publicMetadata(record));
      cursor.continue();
    };
    request.onerror = () => reject(request.error);
    tx.onerror = () => reject(tx.error);
  });
}

export async function getArchivedResponse(id) {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const request = db.transaction(STORE, "readonly").objectStore(STORE).get(Number(id));
    request.onsuccess = () => resolve(request.result || null);
    request.onerror = () => reject(request.error);
  });
}

export async function getAllArchivedResponses() {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const request = db.transaction(STORE, "readonly").objectStore(STORE).getAll();
    request.onsuccess = () => resolve(request.result || []);
    request.onerror = () => reject(request.error);
  });
}

export async function importArchivedResponses(records) {
  if (!Array.isArray(records)) throw new Error("The archive file does not contain a records list.");
  const db = await openDatabase();
  await new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    const store = tx.objectStore(STORE);
    for (const record of records) {
      if (!record || typeof record.root !== "string" || typeof record.url !== "string" || typeof record.timestamp !== "string") continue;
      const { id, bodyBase64, bodyType, ...metadata } = record;
      let body = new Blob([]);
      if (typeof bodyBase64 === "string") {
        const binary = atob(bodyBase64), bytes = Uint8Array.from(binary, char => char.charCodeAt(0));
        body = new Blob([bytes], { type: bodyType || record.contentType || "application/octet-stream" });
      }
      store.add({ ...metadata, body, bodyBytes: body.size, imported: true });
    }
    tx.oncomplete = () => { resolve(); notifyArchiveChanged(); };
    tx.onerror = () => reject(tx.error || new Error("Could not import the response archive."));
    tx.onabort = () => reject(tx.error || new Error("Import was interrupted."));
  });
}
