"""ZAYNOR AIOps demo lab: synthetic observability signals feeding ZAYNOR.

Layout:

- ``demo_app/app.py``      synthetic HTTP service emitting Prometheus
  metrics, structured JSON logs, and Zipkin v2 JSON traces.
- ``aggregator/app.py``    incident aggregator: receives alert clusters
  (Grafana webhook or synthetic JSON files), correlates them into incident
  candidates, collects a bounded telemetry window from the backends, and
  stages an AIOps evidence bundle for ZAYNOR.
- ``compose/``             docker-compose + provisioning for the local
  observability stack (OTel Collector, Prometheus, Loki, Tempo, Grafana).

Authority boundary for the whole lab: the aggregator TRANSFORMS alerts and
telemetry into evidence (observations + provenance only). It never scores,
never labels, never decides. VIGIA, behind ``zaynor analyze`` on the frozen
case, is the only component that decides what the evidence supports.
"""
