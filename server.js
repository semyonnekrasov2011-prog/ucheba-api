const express = require("express");
const multer = require("multer");
const crypto = require("node:crypto");

const app = express();
app.disable("x-powered-by");

const ALLOWED_ORIGIN = "https://ucheba.website.twcstorage.ru";

const SUBJECTS = {
  "алг": "Алгебра",
  "био": "Биология",
  "вер": "Вероятность и статистика",
  "гео": "География",
  "гем": "Геометрия",
  "инф": "Информатика",
  "ист": "История",
  "лит": "Литература",
  "мат": "Математика",
  "обз": "ОБЗР",
  "общ": "Обществознание",
  "рус": "Русский язык",
  "физ": "Физика",
  "хим": "Химия"
};

const SECTIONS = {
  "кон": "Конспекты",
  "учм": "Учебные материалы",
  "упр": "Решение упражнений",
  "зад": "Решение заданий",
  "огэ": "ОГЭ",
  "изл": "Изложения",
  "соч": "Сочинения",
  "про": "Информация по произведениям",
  "опк": "Опорные конспекты",
  "зап": "Записи",
  "дзз": "Фотографии домашних заданий"
};

const HOMEWORK_KEY = "data/homework.json";
const MAX_UPLOAD_BYTES = 20 * 1024 * 1024;

// ---------- CORS and JSON ----------

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  };
}

app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (origin && origin !== ALLOWED_ORIGIN) {
    return res.status(403).json({
      success: false,
      error: "Origin запрещён"
    });
  }

  Object.entries(corsHeaders()).forEach(([name, value]) => {
    res.setHeader(name, value);
  });

  res.setHeader("Cache-Control", "no-store");

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  next();
});

app.use(express.json({ limit: "1mb" }));

function jsonError(res, status, error) {
  return res.status(status).json({ success: false, error });
}

// ---------- Common helpers ----------

function encodeRFC3986(value) {
  return encodeURIComponent(value).replace(/[!'()*]/g, char =>
    "%" + char.charCodeAt(0).toString(16).toUpperCase()
  );
}

function encodeS3Key(key) {
  return key.split("/").map(encodeRFC3986).join("/");
}

function sha256(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function hmac(key, data, encoding) {
  return crypto.createHmac("sha256", key).update(data).digest(encoding);
}

function getSignatureKey(secret, date, region, service) {
  const kDate = hmac(Buffer.from("AWS4" + secret), date);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, service);
  return hmac(kService, "aws4_request");
}

function xmlDecode(value) {
  return value
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'");
}

// ---------- AWS Signature V4 / S3 ----------

async function signedS3Request(env, options = {}) {
  const method = options.method || "GET";
  const key = options.key || "";
  const query = options.query || {};
  const body = options.body ?? Buffer.alloc(0);
  const contentType = options.contentType || "";
  const useWriteKeys = options.write === true;

  const accessKey = useWriteKeys
    ? env.S3_WRITE_ACCESS_KEY_ID
    : env.S3_ACCESS_KEY_ID;

  const secretKey = useWriteKeys
    ? env.S3_WRITE_SECRET_ACCESS_KEY
    : env.S3_SECRET_ACCESS_KEY;

  if (!accessKey || !secretKey) {
    throw new Error(
      useWriteKeys
        ? "Не настроены ключи записи S3"
        : "Не настроены ключи чтения S3"
    );
  }

  const endpoint = (env.S3_ENDPOINT || "").replace(/\/+$/, "");
  const bucket = env.S3_BUCKET;
  const region = env.S3_REGION || "ru-1";

  if (!endpoint || !bucket) {
    throw new Error("Не настроены параметры S3");
  }

  const endpointUrl = new URL(endpoint);
  const canonicalUri =
    endpointUrl.pathname.replace(/\/$/, "") +
    "/" + encodeRFC3986(bucket) +
    (key ? "/" + encodeS3Key(key) : "");

  const queryEntries = Object.entries(query)
    .filter(([, value]) => value !== undefined && value !== null)
    .map(([name, value]) => [
      encodeRFC3986(name),
      encodeRFC3986(String(value))
    ])
    .sort((a, b) => {
      if (a[0] === b[0]) return a[1].localeCompare(b[1]);
      return a[0].localeCompare(b[0]);
    });

  const canonicalQuery = queryEntries
    .map(([name, value]) => `${name}=${value}`)
    .join("&");

  const requestUrl = endpoint + canonicalUri +
    (canonicalQuery ? "?" + canonicalQuery : "");

  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const dateStamp = amzDate.slice(0, 8);

  const payload = Buffer.isBuffer(body) ? body : Buffer.from(body);
  const payloadHash = sha256(payload);
  const host = endpointUrl.host;

  const headersToSign = {
    host,
    "x-amz-content-sha256": payloadHash,
    "x-amz-date": amzDate
  };

  if (contentType) {
    headersToSign["content-type"] = contentType;
  }

  const sortedHeaderNames = Object.keys(headersToSign).sort();
  const canonicalHeaders = sortedHeaderNames
    .map(name => `${name}:${String(headersToSign[name]).trim()}\n`)
    .join("");
  const signedHeaders = sortedHeaderNames.join(";");

  const canonicalRequest = [
    method,
    canonicalUri,
    canonicalQuery,
    canonicalHeaders,
    signedHeaders,
    payloadHash
  ].join("\n");

  const credentialScope = `${dateStamp}/${region}/s3/aws4_request`;
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    credentialScope,
    sha256(canonicalRequest)
  ].join("\n");

  const signingKey = getSignatureKey(secretKey, dateStamp, region, "s3");
  const signature = hmac(signingKey, stringToSign, "hex");

  const authorization =
    `AWS4-HMAC-SHA256 Credential=${accessKey}/${credentialScope}, ` +
    `SignedHeaders=${signedHeaders}, Signature=${signature}`;

  const headers = {
    "x-amz-date": amzDate,
    "x-amz-content-sha256": payloadHash,
    "Authorization": authorization
  };

  if (contentType) headers["Content-Type"] = contentType;

  return fetch(requestUrl, {
    method,
    headers,
    body: method === "GET" || method === "HEAD" ? undefined : payload
  });
}

// ---------- Admin authentication ----------

function createToken(password) {
  const expiresAt = Math.floor(Date.now() / 1000) + 30 * 24 * 60 * 60;
  const payload = Buffer.from(JSON.stringify({
    admin: true,
    exp: expiresAt
  })).toString("base64url");

  const signature = hmac(password, payload, "base64url");

  return {
    token: `${payload}.${signature}`,
    expiresAt
  };
}

function verifyToken(req, env) {
  const authorization = req.headers.authorization || "";

  if (!authorization.startsWith("Bearer ") || !env.ADMIN_PASSWORD) {
    return false;
  }

  const parts = authorization.slice(7).split(".");
  if (parts.length !== 2) return false;

  const [payloadPart, signaturePart] = parts;
  const expected = hmac(env.ADMIN_PASSWORD, payloadPart, "base64url");

  const expectedBuffer = Buffer.from(expected);
  const actualBuffer = Buffer.from(signaturePart);

  if (
    expectedBuffer.length !== actualBuffer.length ||
    !crypto.timingSafeEqual(expectedBuffer, actualBuffer)
  ) {
    return false;
  }

  try {
    const payload = JSON.parse(
      Buffer.from(payloadPart, "base64url").toString("utf8")
    );

    return payload.admin === true &&
      Number(payload.exp) > Math.floor(Date.now() / 1000);
  } catch {
    return false;
  }
}

function requireAdmin(req, res, next) {
  if (!verifyToken(req, process.env)) {
    return jsonError(res, 401, "Требуется авторизация");
  }
  next();
}

// ---------- Filename validation ----------

function parseFilename(filename) {
  if (typeof filename !== "string") return null;

  const match = filename.match(
    /^([a-zа-я]{3})_([a-zа-я]{3})_(\d{4})-(\d{2})-(\d{2})_(\d+)\.(jpg|jpeg|png|webp|pdf)$/i
  );

  if (!match) return null;

  const subjectCode = match[1].toLowerCase();
  const sectionCode = match[2].toLowerCase();

  const year = Number(match[3]);
  const day = Number(match[4]);
  const month = Number(match[5]);

  const number = Number(match[6]);
  const type = match[7].toLowerCase();

  if (!SUBJECTS[subjectCode] || !SECTIONS[sectionCode]) return null;

  const dateObject = new Date(Date.UTC(year, month - 1, day));

  if (
    dateObject.getUTCFullYear() !== year ||
    dateObject.getUTCMonth() !== month - 1 ||
    dateObject.getUTCDate() !== day
  ) {
    return null;
  }

  return {
    subjectCode,
    sectionCode,
    subject: SUBJECTS[subjectCode],
    section: SECTIONS[sectionCode],
    date: `${year}-${String(month).padStart(2, "0")}-${String(day).padStart(2, "0")}`,
    number,
    type
  };
}

// ---------- Materials listing ----------

function parseMaterials(xml) {
  const materials = [];
  const entries = xml.match(/<Contents>[\s\S]*?<\/Contents>/g) || [];

  for (const entry of entries) {
    const keyMatch = entry.match(/<Key>([\s\S]*?)<\/Key>/);
    if (!keyMatch) continue;

    const filename = xmlDecode(keyMatch[1]);
    const parsed = parseFilename(filename);
    if (!parsed) continue;

    materials.push({
      filename,
      subject: parsed.subject,
      section: parsed.section,
      subjectCode: parsed.subjectCode,
      sectionCode: parsed.sectionCode,
      date: parsed.date,
      number: String(parsed.number).padStart(2, "0"),
      type: parsed.type,
      url: `${ALLOWED_ORIGIN}/${encodeS3Key(filename)}`
    });
  }

  return materials;
}

async function getAllMaterials(env) {
  let continuationToken = null;
  const materials = [];
  let truncated = false;

  for (let page = 0; page < 100; page++) {
    const query = {
      "list-type": "2",
      "max-keys": "1000"
    };

    if (continuationToken) {
      query["continuation-token"] = continuationToken;
    }

    const response = await signedS3Request(env, {
      method: "GET",
      query
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(
        `Ошибка получения списка S3 (${response.status}): ${errorText.slice(0, 500)}`
      );
    }

    const xml = await response.text();
    materials.push(...parseMaterials(xml));

    const truncatedMatch = xml.match(
      /<IsTruncated>(true|false)<\/IsTruncated>/
    );

    truncated = truncatedMatch?.[1] === "true";
    if (!truncated) break;

    const tokenMatch = xml.match(
      /<NextContinuationToken>([\s\S]*?)<\/NextContinuationToken>/
    );

    if (!tokenMatch) break;
    continuationToken = xmlDecode(tokenMatch[1]);
  }

  return { materials, truncated };
}

// ---------- Homework JSON in S3 ----------

async function readHomework(env) {
  const response = await signedS3Request(env, {
    method: "GET",
    key: HOMEWORK_KEY
  });

  if (response.status === 404) return {};

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(
      `Ошибка чтения homework.json (${response.status}): ${errorText.slice(0, 500)}`
    );
  }

  const text = await response.text();

  try {
    const data = JSON.parse(text);
    if (!data || typeof data !== "object" || Array.isArray(data)) {
      throw new Error("Неверная структура JSON");
    }
    return data;
  } catch {
    throw new Error("Файл homework.json содержит некорректный JSON");
  }
}

async function writeHomework(env, data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new Error("Переданы некорректные данные домашних заданий");
  }

  const body = JSON.stringify(data, null, 2);
  const response = await signedS3Request(env, {
    method: "PUT",
    key: HOMEWORK_KEY,
    body: Buffer.from(body, "utf8"),
    contentType: "application/json; charset=utf-8",
    write: true
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(
      `Ошибка сохранения homework.json (${response.status}): ${errorText.slice(0, 500)}`
    );
  }

  return true;
}

// ---------- Upload / delete ----------

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_UPLOAD_BYTES, files: 1 }
});

const ALLOWED_TYPES = {
  jpg: ["image/jpeg", "image/jpg"],
  jpeg: ["image/jpeg", "image/jpg"],
  png: ["image/png"],
  webp: ["image/webp"],
  pdf: ["application/pdf"]
};

async function uploadMaterial(req, res) {
  const file = req.file;
  const filename = req.body.filename;

  if (!file) return jsonError(res, 400, "Файл не передан");
  if (typeof filename !== "string") {
    return jsonError(res, 400, "Не указано имя файла");
  }

  const parsed = parseFilename(filename);
  if (!parsed) {
    return jsonError(
      res,
      400,
      "Недопустимое имя файла или неизвестный код предмета/раздела"
    );
  }

  if (!file.size) return jsonError(res, 400, "Файл пустой");

  const expectedTypes = ALLOWED_TYPES[parsed.type];
  if (
    file.mimetype &&
    !expectedTypes.includes(file.mimetype.toLowerCase())
  ) {
    return jsonError(res, 400, "Тип файла не соответствует его расширению");
  }

  const contentType = file.mimetype ||
    (parsed.type === "pdf"
      ? "application/pdf"
      : `image/${parsed.type === "jpg" ? "jpeg" : parsed.type}`);

  const response = await signedS3Request(process.env, {
    method: "PUT",
    key: filename,
    body: file.buffer,
    contentType,
    write: true
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(
      `Ошибка загрузки файла (${response.status}): ${errorText.slice(0, 500)}`
    );
  }

  return res.json({
    success: true,
    filename,
    url: `${ALLOWED_ORIGIN}/${encodeS3Key(filename)}`
  });
}

async function deleteMaterial(req, res) {
  const filename = req.query.filename;

  if (!filename || !parseFilename(filename)) {
    return jsonError(res, 400, "Недопустимое имя файла");
  }

  const response = await signedS3Request(process.env, {
    method: "DELETE",
    key: filename,
    write: true
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(
      `Ошибка удаления файла (${response.status}): ${errorText.slice(0, 500)}`
    );
  }

  return res.json({ success: true, filename });
}

// ---------- API routes ----------

app.get("/", (req, res) => {
  res.json({
    success: true,
    service: "ucheba-api",
    status: "online"
  });
});

app.post("/auth/login", (req, res) => {
  if (!process.env.ADMIN_PASSWORD) {
    return jsonError(res, 500, "Пароль администратора не настроен");
  }

  const password = req.body?.password;
  if (typeof password !== "string" || password !== process.env.ADMIN_PASSWORD) {
    return jsonError(res, 401, "Неверный пароль");
  }

  const result = createToken(process.env.ADMIN_PASSWORD);
  return res.json({
    success: true,
    token: result.token,
    expiresAt: result.expiresAt
  });
});

app.get("/auth/check", (req, res) => {
  return res.json({
    success: true,
    authenticated: verifyToken(req, process.env)
  });
});

app.get("/materials", async (req, res, next) => {
  try {
    const result = await getAllMaterials(process.env);
    return res.json({
      success: true,
      count: result.materials.length,
      materials: result.materials,
      truncated: result.truncated
    });
  } catch (error) {
    next(error);
  }
});

app.get("/homework", requireAdmin, async (req, res, next) => {
  try {
    const homework = await readHomework(process.env);
    return res.json({ success: true, homework });
  } catch (error) {
    next(error);
  }
});

app.put("/homework", requireAdmin, async (req, res, next) => {
  try {
    await writeHomework(process.env, req.body?.homework);
    return res.json({
      success: true,
      message: "Домашние задания сохранены"
    });
  } catch (error) {
    next(error);
  }
});

app.post(
  "/materials/upload",
  requireAdmin,
  upload.single("file"),
  async (req, res, next) => {
    try {
      await uploadMaterial(req, res);
    } catch (error) {
      next(error);
    }
  }
);

app.delete("/materials/delete", requireAdmin, async (req, res, next) => {
  try {
    await deleteMaterial(req, res);
  } catch (error) {
    next(error);
  }
});

// ---------- Errors and server ----------

app.use((req, res) => {
  return jsonError(res, 404, "Маршрут не найден");
});

app.use((error, req, res, next) => {
  console.error("API error:", error);

  if (error instanceof multer.MulterError) {
    if (error.code === "LIMIT_FILE_SIZE") {
      return jsonError(res, 413, "Файл превышает лимит 20 МБ");
    }
    return jsonError(res, 400, "Ошибка обработки загруженного файла");
  }

  if (error instanceof SyntaxError && error.status === 400 && "body" in error) {
    return jsonError(res, 400, "Некорректный JSON");
  }

  return jsonError(res, 500, error?.message || "Внутренняя ошибка API");
});

const PORT = Number(process.env.PORT) || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`ucheba-api запущен на порту ${PORT}`);
});