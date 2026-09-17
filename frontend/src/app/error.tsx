"use client";

interface ErrorPageProps {
  readonly reset: () => void;
}

export default function ErrorPage({ reset }: ErrorPageProps) {
  return (
    <div className="route-placeholder">
      <section aria-labelledby="application-error-title" className="state-panel" data-tone="error">
        <div>
          <h1 id="application-error-title">No se pudo cargar el espacio de trabajo</h1>
          <p>Reintentá la solicitud. Si el problema continúa, volvé al inicio y verificá el caso.</p>
          <div className="state-panel__action">
            <button className="retry-button" onClick={reset} type="button">
              Reintentar
            </button>
          </div>
        </div>
      </section>
    </div>
  );
}
