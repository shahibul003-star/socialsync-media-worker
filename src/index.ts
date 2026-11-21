import { verify } from "./crypto.ts";
export const CONNECTOR_VERSION = "1.0.0";
interface Env {
  MEDIA: R2Bucket;
  MEDIA_SIGNING_SECRET: string;
  APP_ORIGINS: string;
  ALLOWED_IMPORT_HOSTS: string;
}
const MAX = 100 * 1024 * 1024;
function validKey(key: unknown): key is string {
  return (
    typeof key === "string" &&
    /^[a-f\d-]{36}\/[a-f\d-]{36}\/[a-f\d-]{36}$/i.test(key)
  );
}
function allowedSource(url: URL, patterns: string[]) {
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    (url.port && url.port !== "443")
  )
    return false;
  return patterns.some((pattern) =>
    pattern.startsWith("*.")
      ? url.hostname.endsWith(pattern.slice(1)) &&
        url.hostname !== pattern.slice(2)
      : url.hostname === pattern,
  );
}
async function fetchApproved(source: string, env: Env) {
  let url = new URL(source);
  const allowed = env.ALLOWED_IMPORT_HOSTS.split(",").map((v) =>
    v.trim().toLowerCase(),
  );
  for (let i = 0; i < 4; i++) {
    if (!allowedSource(url, allowed))
      throw Error("Source host is not approved for media imports.");
    const response = await fetch(url, {
      redirect: "manual",
      signal: AbortSignal.timeout(85000),
    });
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get("Location");
      if (!location) throw Error("Invalid source redirect.");
      await response.body?.cancel();
      url = new URL(location, url);
      continue;
    }
    if (!response.ok)
      throw Error("Source download failed. Refresh the original download URL.");
    return response;
  }
  throw Error("Too many source redirects.");
}
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const origin = request.headers.get("Origin"),
      origins = env.APP_ORIGINS.split(",").map((v) => v.trim());
    const headers = new Headers({
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      "Access-Control-Allow-Methods": "GET,HEAD,PUT,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type,Range",
      "Access-Control-Expose-Headers": "Content-Length,Content-Range,ETag",
      Vary: "Origin",
    });
    if (origin && origins.includes(origin))
      headers.set("Access-Control-Allow-Origin", origin);
    const finish = (
      body: BodyInit | null,
      status = 200,
      extra?: HeadersInit,
    ) => {
      const merged = new Headers(headers);
      new Headers(extra).forEach((v, k) => merged.set(k, v));
      return new Response(body, { status, headers: merged });
    };
    if (request.method === "OPTIONS") return finish(null, 204);
    try {
      const url = new URL(request.url);
      if (url.pathname.startsWith("/internal/")) {
        if (request.method !== "POST") return finish("Method not allowed", 405);
        const raw = await request.text();
        if (raw.length > 12000) return finish("Payload too large", 413);
        const timestamp = request.headers.get("X-SocialSync-Time") ?? "";
        if (
          !Number.isFinite(Number(timestamp)) ||
          Math.abs(Date.now() - Number(timestamp)) > 60000 ||
          !(await verify(
            `${timestamp}\n${raw}`,
            request.headers.get("X-SocialSync-Signature") ?? "",
            env.MEDIA_SIGNING_SECRET,
          ))
        )
          return finish("Unauthorized", 401);
        const body = JSON.parse(raw);
        if (url.pathname === "/internal/health") return finish(JSON.stringify({ version: CONNECTOR_VERSION, protocol: 1, storage: Boolean(env.MEDIA) }), 200, { "Content-Type": "application/json" });
        if (!validKey(body.key)) return finish("Invalid object key", 400);
        if (url.pathname === "/internal/stat") {
          const object = await env.MEDIA.head(body.key);
          return finish(
            JSON.stringify({
              exists: Boolean(object),
              bytes: object?.size,
              content_type: object?.httpMetadata?.contentType,
            }),
            200,
            { "Content-Type": "application/json" },
          );
        }
        if (url.pathname === "/internal/delete") {
          await env.MEDIA.delete(body.key);
          return finish(JSON.stringify({ ok: true }), 200, {
            "Content-Type": "application/json",
          });
        }
        if (url.pathname === "/internal/import") {
          const existing = await env.MEDIA.head(body.key);
          if (existing)
            return finish(
              JSON.stringify({
                bytes: existing.size,
                content_type: existing.httpMetadata?.contentType,
              }),
              200,
              { "Content-Type": "application/json" },
            );
          const source = await fetchApproved(String(body.url), env);
          const bytes = Number(source.headers.get("Content-Length"));
          const type = (source.headers.get("Content-Type") ?? "").split(";")[0];
          if (
            !bytes ||
            bytes > MAX ||
            !source.body ||
            !/^video\/(mp4|quicktime)$/.test(type)
          ) {
            await source.body?.cancel();
            throw Error(
              "Source must be an MP4/MOV with a known length under 100 MB.",
            );
          }
          await env.MEDIA.put(body.key, source.body, {
            httpMetadata: { contentType: type },
          });
          return finish(JSON.stringify({ bytes, content_type: type }), 200, {
            "Content-Type": "application/json",
          });
        }
        return finish("Not found", 404);
      }
      if (url.pathname !== "/media") return finish("Not found", 404);
      const key = url.searchParams.get("key"),
        expires = Number(url.searchParams.get("expires")),
        access = url.searchParams.get("access");
      if (
        !validKey(key) ||
        !Number.isSafeInteger(expires) ||
        expires < Math.floor(Date.now() / 1000) ||
        !["read", "upload"].includes(access ?? "") ||
        !(await verify(
          `${key}\n${expires}\n${access}`,
          url.searchParams.get("signature") ?? "",
          env.MEDIA_SIGNING_SECRET,
        ))
      )
        return finish("Access expired or invalid", 403);
      if (request.method === "PUT") {
        if (access !== "upload" || (origin && !origins.includes(origin)))
          return finish("Unauthorized", 403);
        if (await env.MEDIA.head(key))
          return finish("This upload already exists", 409);
        const bytes = Number(request.headers.get("Content-Length")),
          type = request.headers.get("Content-Type") ?? "";
        if (
          !bytes ||
          bytes > MAX ||
          !request.body ||
          !/^(image\/(jpeg|png|webp|gif)|video\/(mp4|quicktime))$/.test(type)
        )
          return finish("Unsupported media or size", 400);
        await env.MEDIA.put(key, request.body, {
          httpMetadata: { contentType: type },
        });
        return finish(null, 201);
      }
      if (access !== "read" || !["GET", "HEAD"].includes(request.method))
        return finish("Method not allowed", 405);
      const requestedRange =
        request.method !== "HEAD" && request.headers.has("Range");
      const object =
        request.method === "HEAD"
          ? await env.MEDIA.head(key)
          : await env.MEDIA.get(
              key,
              requestedRange ? { range: request.headers } : undefined,
            );
      if (!object) return finish("Original unavailable", 404);
      object.writeHttpMetadata(headers);
      headers.set("ETag", object.httpEtag);
      headers.set("Cache-Control", "private, no-store");
      const range =
        requestedRange && "range" in object ? object.range : undefined;
      if (range && "offset" in range) {
        const offset = range.offset ?? 0,
          length = range.length ?? object.size;
        headers.set(
          "Content-Range",
          `bytes ${offset}-${offset + length - 1}/${object.size}`,
        );
        headers.set("Content-Length", String(length));
      } else headers.set("Content-Length", String(object.size));
      headers.set("Accept-Ranges", "bytes");
      return finish(
        request.method === "HEAD" ? null : (object as R2ObjectBody).body,
        range ? 206 : 200,
      );
    } catch {
      return finish(
        JSON.stringify({
          error:
            "Media operation failed. Verify the source URL, file type, size and storage configuration.",
        }),
        400,
        { "Content-Type": "application/json" },
      );
    }
  },
};
