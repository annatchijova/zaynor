import { StatePanel } from "@/components/ui/state-panel";

export default function Loading() {
  return (
    <div className="route-placeholder">
      <StatePanel
        detail="Preparing the case workspace."
        title="Loading case context"
        tone="loading"
      />
    </div>
  );
}
