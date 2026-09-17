import caseOverviewFixture from "./case-001.json";
import evidenceFixture from "./case-001-evidence.json";
import emptyCasesFixture from "./empty-cases.json";
import narrativesFixture from "./narratives.json";
import negativeResponsesFixture from "./negative-responses.json";

import caseCase008ParanoiaPerimetroOverview from "./cases/case_008_paranoia_perimetro.json";
import caseCase008ParanoiaPerimetroEvidence from "./cases/case_008_paranoia_perimetro-evidence.json";
import caseCase024ParacaidistaTimestompingOverview from "./cases/case_024_paracaidista_timestomping.json";
import caseCase024ParacaidistaTimestompingEvidence from "./cases/case_024_paracaidista_timestomping-evidence.json";
import caseCase026VentrilocuoProcessHollowingOverview from "./cases/case_026_ventrilocuo_process_hollowing.json";
import caseCase026VentrilocuoProcessHollowingEvidence from "./cases/case_026_ventrilocuo_process_hollowing-evidence.json";
import caseCase083SacrificioDelPeonOverview from "./cases/case_083_sacrificio_del_peon.json";
import caseCase083SacrificioDelPeonEvidence from "./cases/case_083_sacrificio_del_peon-evidence.json";
import caseCase093DeepfakeEstiloOverview from "./cases/case_093_deepfake_estilo.json";
import caseCase093DeepfakeEstiloEvidence from "./cases/case_093_deepfake_estilo-evidence.json";
import caseVigiaReal008Overview from "./cases/VIGIA-REAL-008.json";
import caseVigiaReal008Evidence from "./cases/VIGIA-REAL-008-evidence.json";
import caseVigiaRealSony001Overview from "./cases/VIGIA-REAL-SONY-001.json";
import caseVigiaRealSony001Evidence from "./cases/VIGIA-REAL-SONY-001-evidence.json";
import caseVigiaTuck2019Overview from "./cases/VIGIA-TUCK-2019.json";
import caseVigiaTuck2019Evidence from "./cases/VIGIA-TUCK-2019-evidence.json";
import caseVigiaNgdc001Overview from "./cases/VIGIA-NGDC-001.json";
import caseVigiaNgdc001Evidence from "./cases/VIGIA-NGDC-001-evidence.json";
import caseFfGenuine001Overview from "./cases/FF-GENUINE-001.json";
import caseFfGenuine001Evidence from "./cases/FF-GENUINE-001-evidence.json";
import caseVigiaFlareon6Overview from "./cases/VIGIA-FLAREON-6.json";
import caseVigiaFlareon6Evidence from "./cases/VIGIA-FLAREON-6-evidence.json";
import caseVigiaNitrobaM57001Overview from "./cases/VIGIA-NITROBA-M57-001.json";
import caseVigiaNitrobaM57001Evidence from "./cases/VIGIA-NITROBA-M57-001-evidence.json";
import caseVigiaRealColonial001Overview from "./cases/VIGIA-REAL-COLONIAL-001.json";
import caseVigiaRealColonial001Evidence from "./cases/VIGIA-REAL-COLONIAL-001-evidence.json";
import caseVigiaRealTarget001Overview from "./cases/VIGIA-REAL-TARGET-001.json";
import caseVigiaRealTarget001Evidence from "./cases/VIGIA-REAL-TARGET-001-evidence.json";
import caseVigiaFp003Overview from "./cases/VIGIA-FP-003.json";
import caseVigiaFp003Evidence from "./cases/VIGIA-FP-003-evidence.json";
import caseVigiaNgdc003Overview from "./cases/VIGIA-NGDC-003.json";
import caseVigiaNgdc003Evidence from "./cases/VIGIA-NGDC-003-evidence.json";
import caseVigiaFp001Overview from "./cases/VIGIA-FP-001.json";
import caseVigiaFp001Evidence from "./cases/VIGIA-FP-001-evidence.json";
import caseVigiaAndroid11001Overview from "./cases/VIGIA-ANDROID11-001.json";
import caseVigiaAndroid11001Evidence from "./cases/VIGIA-ANDROID11-001-evidence.json";
import caseFpCulturalClean001Overview from "./cases/FP-CULTURAL-CLEAN-001.json";
import caseFpCulturalClean001Evidence from "./cases/FP-CULTURAL-CLEAN-001-evidence.json";
import caseVigiaFp002Overview from "./cases/VIGIA-FP-002.json";
import caseVigiaFp002Evidence from "./cases/VIGIA-FP-002-evidence.json";

import type {
  CaseOverview,
  CaseSummary,
  EvidenceArtifact,
  ApiError,
  NarrativeAnswer,
  SystemHealth,
} from "../contracts";

export const case001 = caseOverviewFixture as CaseOverview;
export const case001Evidence = evidenceFixture as unknown as readonly EvidenceArtifact[];
export const case001Narratives = narrativesFixture as Readonly<Record<string, NarrativeAnswer>>;

/**
 * A curated demo corpus of real, sealed ZAYNOR verdicts -- run through the
 * actual freeze/analyze pipeline against real forensic case data (5 from
 * this repo's own casos/, 15 from VIGIA's own case corpus: Nitroba,
 * Cridex, Colonial Pipeline, Sony, Target, and others), not fabricated.
 * Spanish name/description authored per case; result_sha256, findings,
 * and verdicts are the real sealed output. See
 * docs/adr/... (or ask the maintainer) for how this corpus was built.
 */
export const demoCases: readonly CaseOverview[] = [
  caseCase008ParanoiaPerimetroOverview as CaseOverview,
  caseCase024ParacaidistaTimestompingOverview as CaseOverview,
  caseCase026VentrilocuoProcessHollowingOverview as CaseOverview,
  caseCase083SacrificioDelPeonOverview as CaseOverview,
  caseCase093DeepfakeEstiloOverview as CaseOverview,
  caseVigiaReal008Overview as CaseOverview,
  caseVigiaRealSony001Overview as CaseOverview,
  caseVigiaTuck2019Overview as CaseOverview,
  caseVigiaNgdc001Overview as CaseOverview,
  caseFfGenuine001Overview as CaseOverview,
  caseVigiaFlareon6Overview as CaseOverview,
  caseVigiaNitrobaM57001Overview as CaseOverview,
  caseVigiaRealColonial001Overview as CaseOverview,
  caseVigiaRealTarget001Overview as CaseOverview,
  caseVigiaFp003Overview as CaseOverview,
  caseVigiaNgdc003Overview as CaseOverview,
  caseVigiaFp001Overview as CaseOverview,
  caseVigiaAndroid11001Overview as CaseOverview,
  caseFpCulturalClean001Overview as CaseOverview,
  caseVigiaFp002Overview as CaseOverview,
];

export const demoCaseEvidence: Readonly<Record<string, readonly EvidenceArtifact[]>> = {
  "case_008_paranoia_perimetro": caseCase008ParanoiaPerimetroEvidence as unknown as readonly EvidenceArtifact[],
  "case_024_paracaidista_timestomping": caseCase024ParacaidistaTimestompingEvidence as unknown as readonly EvidenceArtifact[],
  "case_026_ventrilocuo_process_hollowing": caseCase026VentrilocuoProcessHollowingEvidence as unknown as readonly EvidenceArtifact[],
  "case_083_sacrificio_del_peon": caseCase083SacrificioDelPeonEvidence as unknown as readonly EvidenceArtifact[],
  "case_093_deepfake_estilo": caseCase093DeepfakeEstiloEvidence as unknown as readonly EvidenceArtifact[],
  "VIGIA-REAL-008": caseVigiaReal008Evidence as unknown as readonly EvidenceArtifact[],
  "VIGIA-REAL-SONY-001": caseVigiaRealSony001Evidence as unknown as readonly EvidenceArtifact[],
  "VIGIA-TUCK-2019": caseVigiaTuck2019Evidence as unknown as readonly EvidenceArtifact[],
  "VIGIA-NGDC-001": caseVigiaNgdc001Evidence as unknown as readonly EvidenceArtifact[],
  "FF-GENUINE-001": caseFfGenuine001Evidence as unknown as readonly EvidenceArtifact[],
  "VIGIA-FLAREON-6": caseVigiaFlareon6Evidence as unknown as readonly EvidenceArtifact[],
  "VIGIA-NITROBA-M57-001": caseVigiaNitrobaM57001Evidence as unknown as readonly EvidenceArtifact[],
  "VIGIA-REAL-COLONIAL-001": caseVigiaRealColonial001Evidence as unknown as readonly EvidenceArtifact[],
  "VIGIA-REAL-TARGET-001": caseVigiaRealTarget001Evidence as unknown as readonly EvidenceArtifact[],
  "VIGIA-FP-003": caseVigiaFp003Evidence as unknown as readonly EvidenceArtifact[],
  "VIGIA-NGDC-003": caseVigiaNgdc003Evidence as unknown as readonly EvidenceArtifact[],
  "VIGIA-FP-001": caseVigiaFp001Evidence as unknown as readonly EvidenceArtifact[],
  "VIGIA-ANDROID11-001": caseVigiaAndroid11001Evidence as unknown as readonly EvidenceArtifact[],
  "FP-CULTURAL-CLEAN-001": caseFpCulturalClean001Evidence as unknown as readonly EvidenceArtifact[],
  "VIGIA-FP-002": caseVigiaFp002Evidence as unknown as readonly EvidenceArtifact[],
};

export const demoCaseMeta: Readonly<Record<string, { readonly name: string; readonly description: string }>> = {
  "case_008_paranoia_perimetro": { name: "La Paranoia del Perímetro", description: "Usuario entra al sistema y ejecuta ciclos de whoami/netstat/w/ps aux cada 300s exactos durante 40 minutos (8 ciclos). Sin modificaciones ni exfiltración. La hipervigilancia periódica delata consciencia de culpa de actor infiltrado." },
  "case_024_paracaidista_timestomping": { name: "El Paracaidista — Timestomping Forense", description: "system_updater.elf con mtime/atime/crtime copiados de binarios legítimos de 2022. Pero ctime: hace 3 horas. MFT entry #147823 asignado después del #147822 (que es de 2026) pero lleva timestamp de 2022. 7 ceros en sub-segundos firman la herramienta de timestomping." },
  "case_026_ventrilocuo_process_hollowing": { name: "El Ventrílocuo — Process Hollowing", description: "svchost.exe (hash limpio, firma Microsoft válida) ejecutándose desde C:\Users\Public\Downloads\, parent cmd.exe, sección .text con permisos RWX, manteniendo 1GB exfiltrado a AS en Ucrania. Firewall reporta 0 bytes." },
  "case_083_sacrificio_del_peon": { name: "El Sacrificio del Peón", description: "Analista senior se auto-denuncia por sesión SSH abierta para crear coartada de honestidad extrema. Mientras el equipo audita su cuenta con benevolencia, un cron job instalado 5 minutos antes de la denuncia exfiltra datos bajo identidad de servicio de sistema." },
  "case_093_deepfake_estilo": { name: "El Deepfake de Estilo", description: "15 commits imitan el estilo del Arquitecto Jefe (espaciado, errores gramaticales, TTR) con precisión estadística de 0.97, superior a la varianza humana biológica (0.82). Subidos vía API key genérica a las 4AM mientras el arquitecto estaba desconectado." },
  "VIGIA-REAL-008": { name: "Troyano bancario Cridex — volcado de memoria", description: "Volcado de memoria (cridex.vmem) de una máquina Windows XP SP2 infectada con el troyano bancario Cridex (Feodo/Bugat, antecesor de Dridex). El malware inyecta código en explorer.exe y se comunica con su C2." },
  "VIGIA-REAL-SONY-001": { name: "Guardians of Peace — Brecha destructiva en Sony Pictures (2014)", description: "El 24 de noviembre de 2014, Sony Pictures Entertainment sufrió un ciberataque destructivo de 'Guardians of Peace', combinando exfiltración masiva de datos con borrado de infraestructura." },
  "VIGIA-TUCK-2019": { name: "Sospecha de ecoterrorismo en incendios de Seattle (2008)", description: "Artículo del New York Times sobre incendios intencionales atribuidos al Earth Liberation Front (E.L.F.) en cinco mansiones de lujo en Maltby, Washington, en 2008." },
  "VIGIA-NGDC-001": { name: "Infiltración física y canal encubierto — National Gallery DC (2012)", description: "Carry, simpatizante de una causa extranjera, es reclutado para orquestrar el vandalismo de una obra de arte extranjera en la National Gallery de Washington DC. Evidencia extraída de una imagen forense E01 de su tablet." },
  "FF-GENUINE-001": { name: "Ataque real con bandera falsa plantada", description: "Compromiso real confirmado en memoria (process hollowing y volcado de credenciales LSASS). Sobre el ataque genuino, el operador plantó cadenas en ruso sospechosamente prolijas para simular un origen que no es el real." },
  "VIGIA-FLAREON-6": { name: "FLARE-On 6 (2019) — Colección de desafíos CTF de malware", description: "Conjunto de 12 desafíos de ingeniería inversa de malware publicado en 2019 por el equipo FLARE de FireEye, usado aquí como corpus de evidencia sintética." },
  "VIGIA-NITROBA-M57-001": { name: "Nitroba — Atribución de identidad en captura de red (M57 Patents, DFRWS 2009)", description: "Captura de tráfico de red del desafío forense M57 Patents (DFRWS 2009). Se busca identificar qué empleada envió un correo de acoso desde una red compartida, cruzando sesiones HTTP, cookies y tráfico de correo." },
  "VIGIA-REAL-COLONIAL-001": { name: "DarkSide — Ransomware en infraestructura crítica (Colonial Pipeline, 2021)", description: "El 7 de mayo de 2021, Colonial Pipeline sufrió un ataque de ransomware del grupo DarkSide que forzó el cierre del oleoducto de combustible más grande de EE. UU." },
  "VIGIA-REAL-TARGET-001": { name: "BlackPOS — Brecha en la cadena de suministro de Target (2013)", description: "Entre noviembre y diciembre de 2013, Target sufrió una de las mayores brechas de datos retail de la historia, iniciada por credenciales robadas a un proveedor externo de HVAC." },
  "VIGIA-FP-003": { name: "El post-it del administrador", description: "Un usuario de finanzas anota su contraseña en un post-it visible por una cámara de una sala de reuniones. Un colega la ve y la comparte por chat interno; el usuario la cambia. No se abusa de la credencial." },
  "VIGIA-NGDC-003": { name: "Vigilancia encuestionada de un padre — National Gallery DC (2012)", description: "Joe instala un keylogger (LogKext) en la MacBook Air familiar antes de su divorcio, declarando que su intención era monitorear a su hija de 15 años. La intención declarada y la evidencia técnica entran en tensión." },
  "VIGIA-FP-001": { name: "Escaneo de red administrativo autorizado", description: "Un escaneo nmap agresivo (-sS -p- sobre /24) ejecutado desde una estación de trabajo administrativa. El patrón técnico se parece a un reconocimiento hostil, pero el contexto es una tarea autorizada." },
  "VIGIA-ANDROID11-001": { name: "Imagen forense de Android 11", description: "Archivo forense de un dispositivo Android 11 (10.94 GB), con verificación de hash del archivo externo e interno, usado como evidencia de línea base para análisis de dispositivo móvil." },
  "FP-CULTURAL-CLEAN-001": { name: "Marcadores culturales sin incidente real", description: "Un desarrollador en Torzhok, Rusia: nombres de archivo en cirílico, teclado ruso, huso horario UTC+3. Memoria, LSASS y kernel están limpios. No hubo incidente: los marcadores culturales son configuración nativa, no una pista plantada." },
  "VIGIA-FP-002": { name: "Backup legítimo con patrón de exfiltración", description: "Un script de backup documentado y aprobado por el CISO copia 500GB por noche a un proveedor cloud aprobado usando rsync. El volumen y el patrón de tráfico imitan una exfiltración masiva." },
};

export const caseSummaries: readonly CaseSummary[] = [
  {
    case_id: case001.case_id,
    name: "Sesión administrativa fuera de horario",
    verdict: case001.authoritative_result.verdict,
    seal_status: case001.seal.status,
    updated_at: case001.audit.checked_at,
  },
  ...demoCases.map((overview) => ({
    case_id: overview.case_id,
    name: demoCaseMeta[overview.case_id]?.name ?? null,
    verdict: overview.authoritative_result.verdict,
    seal_status: overview.seal.status,
    updated_at: overview.audit.checked_at,
  })),
];

export const operationalHealth: SystemHealth = {
  status: "OPERATIONAL",
  engine: "AVAILABLE",
  ollama: "NOT_CONFIGURED",
};

export const emptyCaseSummaries = emptyCasesFixture as readonly CaseSummary[];

export const mockErrors = negativeResponsesFixture as Readonly<Record<string, ApiError>>;

export const unavailableHealth: SystemHealth = {
  status: "UNAVAILABLE",
  engine: "UNAVAILABLE",
  ollama: "UNAVAILABLE",
};
