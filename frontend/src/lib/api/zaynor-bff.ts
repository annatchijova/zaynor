const cacheControl = "no-store";
const caseIdPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const reportFormats = new Set(["md", "html", "pdf"]);
const maxRequestBytes = 64 * 1024;
const bffBasePath = "/api/zaynor";

type FetchImplementation = (input: string, init?: RequestInit) => Promise<Response>;

export interface ZaynorBffOptions {
  readonly backendBaseUrl: string;
  readonly fetchImplementation?: FetchImplementation;
}

function errorResponse(status: number, code: string, message: string): Response {
  return Response.json(
    { code, message, request_id: null },
    { status, headers: { "Cache-Control": cacheControl } },
  );
}

function isAllowedGetPath(path: readonly string[]): boolean {
  if (path.length === 1 && (path[0] === "health" || path[0] === "cases")) {
    return true;
  }

  if (path.length < 2 || path[0] !== "cases" || !caseIdPattern.test(path[1] ?? "")) {
    return false;
  }

  const suffix = path.slice(2);
  return (
    suffix.length === 0 ||
    (suffix.length === 1 && ["result", "audit", "evidence", "investigation"].includes(suffix[0] ?? "")) ||
    (suffix.length === 2 && suffix[0] === "reports" && reportFormats.has(suffix[1] ?? "")) ||
    (suffix.length === 3 &&
      suffix[0] === "reports" &&
      reportFormats.has(suffix[1] ?? "") &&
      suffix[2] === "download")
  );
}

function isAllowedPostPath(path: readonly string[]): boolean {
  if (path[0] !== "cases" || !caseIdPattern.test(path[1] ?? "")) {
    return false;
  }

  return (
    (path.length === 3 && path[2] === "chat") ||
    (path.length === 4 && path[2] === "investigations" && path[3] === "proposals")
  );
}

function normalizeBackendBaseUrl(baseUrl: string): string {
  const parsed = new URL(baseUrl);

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new TypeError("ZAYNOR_API_BASE_URL must use HTTP or HTTPS.");
  }

  if (parsed.search || parsed.hash) {
    throw new TypeError("ZAYNOR_API_BASE_URL must not include a query string or fragment.");
  }

  return parsed.toString().replace(/\/$/, "");
}

function responseHeaders(upstream: Response): Headers {
  const headers = new Headers({ "Cache-Control": cacheControl });
  const contentType = upstream.headers.get("content-type");
  const contentDisposition = upstream.headers.get("content-disposition");

  if (contentType) {
    headers.set("Content-Type", contentType);
  }

  if (contentDisposition) {
    headers.set("Content-Disposition", contentDisposition);
  }

  return headers;
}

function reportDescriptorPath(path: readonly string[]): string | null {
  if (path.length !== 4 || path[0] !== "cases" || path[2] !== "reports" || !reportFormats.has(path[3] ?? "")) {
    return null;
  }

  return `/cases/${path[1]}/reports/${path[3]}/download`;
}

async function rewriteReportDescriptor(upstream: Response, path: readonly string[]): Promise<Response> {
  const expectedDownloadPath = reportDescriptorPath(path);

  if (!expectedDownloadPath || !upstream.ok) {
    return new Response(upstream.body, { status: upstream.status, headers: responseHeaders(upstream) });
  }

  try {
    const payload: unknown = await upstream.json();
    if (
      typeof payload !== "object" ||
      payload === null ||
      Array.isArray(payload) ||
      (payload as Readonly<Record<string, unknown>>).format !== path[3] ||
      (payload as Readonly<Record<string, unknown>>).download_url !== expectedDownloadPath
    ) {
      return errorResponse(502, "INTERNAL_ERROR", "El servicio devolvió un descriptor de reporte incompatible.");
    }

    return Response.json(
      { ...payload, download_url: `${bffBasePath}${expectedDownloadPath}` },
      { status: upstream.status, headers: { "Cache-Control": cacheControl } },
    );
  } catch {
    return errorResponse(502, "INTERNAL_ERROR", "El servicio devolvió un descriptor de reporte incompatible.");
  }
}

async function readJsonBody(request: Request): Promise<ArrayBuffer | Response> {
  const contentType = request.headers.get("content-type") ?? "";

  if (!/^application\/json(?:\s*;|$)/i.test(contentType)) {
    return errorResponse(415, "INVALID_REQUEST", "La solicitud debe usar contenido JSON.");
  }

  const declaredLength = request.headers.get("content-length");
  if (declaredLength && (!/^\d+$/.test(declaredLength) || Number(declaredLength) > maxRequestBytes)) {
    return errorResponse(413, "INVALID_REQUEST", "La solicitud supera el tamaño permitido.");
  }

  const body = await request.arrayBuffer();
  if (body.byteLength > maxRequestBytes) {
    return errorResponse(413, "INVALID_REQUEST", "La solicitud supera el tamaño permitido.");
  }

  return body;
}

export function createZaynorBff({
  backendBaseUrl,
  fetchImplementation = globalThis.fetch.bind(globalThis),
}: ZaynorBffOptions) {
  const normalizedBaseUrl = normalizeBackendBaseUrl(backendBaseUrl);

  return async function handle(request: Request, path: readonly string[]): Promise<Response> {
    if (new URL(request.url).search) {
      return errorResponse(400, "INVALID_REQUEST", "La ruta solicitada no admite parámetros de consulta.");
    }

    const allowed = request.method === "GET" ? isAllowedGetPath(path) : request.method === "POST" && isAllowedPostPath(path);
    if (!allowed) {
      return errorResponse(404, "CASE_NOT_FOUND", "No se encontró el recurso solicitado.");
    }

    const body = request.method === "POST" ? await readJsonBody(request) : undefined;
    if (body instanceof Response) {
      return body;
    }

    try {
      const upstream = await fetchImplementation(`${normalizedBaseUrl}/${path.join("/")}`, {
        method: request.method,
        body,
        cache: "no-store",
        headers: {
          Accept: request.method === "GET" && path.at(-1) === "download" ? "*/*" : "application/json",
          ...(body ? { "Content-Type": "application/json" } : {}),
        },
      });

      if (request.method === "GET" && reportDescriptorPath(path)) {
        return rewriteReportDescriptor(upstream, path);
      }

      return new Response(upstream.body, { status: upstream.status, headers: responseHeaders(upstream) });
    } catch {
      return errorResponse(503, "INTERNAL_ERROR", "No se pudo establecer comunicación con el servicio local.");
    }
  };
}
