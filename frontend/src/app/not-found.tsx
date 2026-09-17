import Link from "next/link";

import { StatePanel } from "@/components/ui/state-panel";

export default function NotFound() {
  return (
    <div className="route-placeholder">
      <StatePanel
        action={
          <Link className="text-link" href="/">
            Volver al inicio
          </Link>
        }
        detail="Verificá el identificador del caso o volvé a las rutas disponibles de la consola."
        title="No se encontró este espacio de trabajo"
        tone="error"
      />
    </div>
  );
}
