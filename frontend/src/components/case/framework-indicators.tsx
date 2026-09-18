import styles from "./framework-indicators.module.css";

interface Technique {
  readonly id: string;
  readonly name: string;
}

interface FrameworkCaseData {
  readonly source: string;
  readonly sourceKind: string;
  readonly techniques: readonly Technique[];
}

const TECHNIQUES: Readonly<Record<string, string>> = {
  "T1003": "OS Credential Dumping",
  "T1040": "Network Sniffing",
  "T1041": "Exfiltration Over C2 Channel",
  "T1055": "Process Injection",
  "T1055.012": "Process Injection: Process Hollowing",
  "T1059": "Command and Scripting Interpreter",
  "T1071": "Application Layer Protocol",
  "T1071.001": "Web Protocols",
  "T1078": "Valid Accounts",
  "T1195": "Supply Chain Compromise",
  "T1485": "Data Destruction",
  "T1490": "Inhibit System Recovery",
  "T1550.004": "Use Alternate Authentication Material: Web Session Cookie",
  "T1557": "Adversary-in-the-Middle",
  "T1566": "Phishing",
  "T1567": "Exfiltration Over Web Service",
  "T1583": "Acquire Infrastructure",
  "T1589": "Gather Victim Identity Information",
  "T1593": "Search Open Websites/Domains",
  "T1595": "Active Scanning",
  "T1070.006": "Indicator Removal: Timestomp",
};

// These IDs are copied from the canonical cases' expected_mitre_ttps fields
// and from the explicit VIGÍA technique references in the case fixtures.
// They are contextual mappings, not additional authoritative findings.
const CASE_DATA: Readonly<Record<string, FrameworkCaseData>> = {
  "VIGIA-NITROBA-M57-001": {
    source: "DFRWS 2009 M57 Patents Challenge (nitroba.pcap)",
    sourceKind: "Public forensic dataset",
    techniques: ["T1078", "T1040", "T1550.004"].map((id) => ({ id, name: TECHNIQUES[id] })),
  },
  "VIGIA-REAL-008": {
    source: "Volatility Foundation — Cridex memory sample",
    sourceKind: "Public memory-forensics dataset",
    techniques: ["T1055", "T1557", "T1071.001", "T1003"].map((id) => ({ id, name: TECHNIQUES[id] })),
  },
  "VIGIA-REAL-COLONIAL-001": {
    source: "Public reporting reconstruction — Colonial Pipeline (2021)",
    sourceKind: "Public incident reconstruction",
    techniques: ["T1078", "T1486", "T1041", "T1567", "T1490", "T1583", "T1595"].map((id) => ({ id, name: TECHNIQUES[id] })),
  },
  "VIGIA-REAL-SONY-001": {
    source: "Public reporting reconstruction — Sony Pictures (2014)",
    sourceKind: "Public incident reconstruction",
    techniques: ["T1566", "T1485", "T1041", "T1071", "T1491", "T1589", "T1593"].map((id) => ({ id, name: TECHNIQUES[id] ?? "Technique recorded by VIGÍA" })),
  },
  "VIGIA-REAL-TARGET-001": {
    source: "Public reporting reconstruction — Target (2013)",
    sourceKind: "Public incident reconstruction",
    techniques: ["T1195", "T1071", "T1059", "T1041", "T1078", "T1567", "T1589"].map((id) => ({ id, name: TECHNIQUES[id] })),
  },
  "case_024_paracaidista_timestomping": {
    source: "VIGÍA canonical intentionality corpus — timestomping fixture",
    sourceKind: "Canonical adversarial fixture",
    techniques: [{ id: "T1070.006", name: TECHNIQUES["T1070.006"] }],
  },
  "case_026_ventrilocuo_process_hollowing": {
    source: "VIGÍA canonical intentionality corpus — process hollowing fixture",
    sourceKind: "Canonical adversarial fixture",
    techniques: [{ id: "T1055.012", name: TECHNIQUES["T1055.012"] }],
  },
  "case_008_paranoia_perimetro": {
    source: "VIGÍA canonical intentionality corpus",
    sourceKind: "Canonical adversarial fixture",
    techniques: [],
  },
  "case_083_sacrificio_del_peon": {
    source: "VIGÍA canonical intentionality corpus",
    sourceKind: "Canonical adversarial fixture",
    techniques: [],
  },
  "case_093_deepfake_estilo": {
    source: "VIGÍA canonical intentionality corpus",
    sourceKind: "Canonical adversarial fixture",
    techniques: [],
  },
};

export function getFrameworkCaseData(caseId: string): FrameworkCaseData | null {
  return CASE_DATA[caseId] ?? null;
}

export function FrameworkIndicators({ caseId }: { readonly caseId: string }) {
  const data = getFrameworkCaseData(caseId);

  if (!data) {
    return null;
  }

  return (
    <section aria-labelledby="framework-indicators-title" className={styles.panel}>
      <div>
        <p className={styles.eyebrow}>Contexto de corpus</p>
        <h2 id="framework-indicators-title">Indicadores MITRE ATT&amp;CK</h2>
        <p className={styles.source}>
          {data.source} · {data.sourceKind}
        </p>
      </div>
      <div className={styles.techniques}>
        {data.techniques.length ? (
          data.techniques.map((technique) => (
            <a
              className={styles.technique}
              href={`https://attack.mitre.org/techniques/${technique.id.replace(".", "/")}`}
              key={technique.id}
              rel="noreferrer"
              target="_blank"
            >
              <strong>{technique.id}</strong>
              <span>{technique.name}</span>
            </a>
          ))
        ) : (
          <p className={styles.empty}>El bundle canónico no declara un TTP MITRE explícito para este caso.</p>
        )}
      </div>
      <div className={styles.explanations}>
        <article>
          <strong>¿Qué es MITRE ATT&amp;CK?</strong>
          <p>Una base de conocimiento que describe tácticas y técnicas observadas en operaciones adversarias. Los códigos enlazados ayudan a investigar y comparar casos.</p>
        </article>
        <article>
          <strong>¿Qué aporta NIST?</strong>
          <p>El ciclo de respuesta a incidentes de NIST SP 800-61: detectar y analizar, contener, erradicar y recuperar, y aprender después del incidente.</p>
        </article>
      </div>
      <div className={styles.nistPhases} aria-label="NIST incident response lifecycle">
        <span>01 Detectar y analizar</span>
        <span>02 Contener</span>
        <span>03 Erradicar y recuperar</span>
        <span>04 Actividad post-incidente</span>
      </div>
      <p className={styles.disclaimer}>
        MITRE y NIST son contexto de clasificación para orientar la investigación. No agregan findings, no cambian el veredicto y no sustituyen la verificación del sello.
      </p>
    </section>
  );
}
