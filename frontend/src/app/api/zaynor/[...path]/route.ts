import { createZaynorBff } from "@/lib/api/zaynor-bff";

function handlerForEnvironment() {
  const backendBaseUrl = process.env.ZAYNOR_API_BASE_URL;

  if (!backendBaseUrl) {
    return null;
  }

  try {
    return createZaynorBff({ backendBaseUrl });
  } catch {
    return null;
  }
}

async function handle(request: Request, context: RouteContext<"/api/zaynor/[...path]">): Promise<Response> {
  const handler = handlerForEnvironment();
  if (!handler) {
    return Response.json(
      {
        code: "INTERNAL_ERROR",
        message: "El proxy local no está configurado correctamente.",
        request_id: null,
      },
      { status: 503, headers: { "Cache-Control": "no-store" } },
    );
  }

  const { path } = await context.params;
  return handler(request, path);
}

export async function GET(request: Request, context: RouteContext<"/api/zaynor/[...path]">): Promise<Response> {
  return handle(request, context);
}

export async function POST(request: Request, context: RouteContext<"/api/zaynor/[...path]">): Promise<Response> {
  return handle(request, context);
}
