import { ApiClientError } from "@/lib/api";

export interface NarrationErrorPresentation {
  readonly detail: string;
  readonly title: string;
}

export function presentNarrationError(error: unknown): NarrationErrorPresentation {
  if (error instanceof ApiClientError && error.code === "OLLAMA_UNAVAILABLE") {
    return {
      title: "La narración local no está disponible",
      detail:
        "El resultado autoritativo permanece disponible y no fue modificado. Volvé a intentarlo cuando el modelo local esté disponible.",
    };
  }

  if (error instanceof ApiClientError && error.code === "POLICY_REJECTED") {
    return {
      title: "La solicitud no puede narrarse",
      detail:
        "La pregunta excede el paquete autoritativo disponible. Reformulala sobre el resultado, sus evidencias o sus incertidumbres.",
    };
  }

  if (error instanceof ApiClientError && error.code === "INVALID_REQUEST") {
    return {
      title: "La pregunta no tiene una respuesta autorizada",
      detail:
        "Elegí una de las preguntas sugeridas o consultá únicamente sobre el paquete sellado del caso.",
    };
  }

  return {
    title: "No se pudo obtener la explicación",
    detail:
      "No se recibió una narración verificable. El resultado autoritativo y el sello del caso no fueron modificados.",
  };
}
