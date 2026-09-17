import { StatePanel } from "@/components/ui/state-panel";

export default function Loading() {
  return (
    <div className="route-placeholder">
      <StatePanel
        detail="Preparando el espacio de trabajo del caso."
        title="Cargando contexto del caso"
        tone="loading"
      />
    </div>
  );
}
