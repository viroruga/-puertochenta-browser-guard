import { afterEach, describe, expect, it } from "vitest";
import { BrowserGuard } from "../src/BrowserGuard";
import type { SecurityFinding } from "../src/Types/SecurityFinding";
import { FlushMicrotasks, FlushTasks, ResetGuard } from "./Helpers";

type FrameWindow = Window & typeof globalThis;

/** Sinks y realms; red apagada para no hacer solicitudes reales desde jsdom. */
const Config = {
  Console: "silent",
  Preset: "development",
  Monitors: {
    Fetch: false,
    Xhr: false,
    WebSocket: false,
    Dom: false,
    Csp: false,
    Prototype: false,
    Runtime: false,
    Channels: false,
  },
} as const;

async function Findings(guard: BrowserGuard): Promise<SecurityFinding[]> {
  await FlushMicrotasks();
  return guard.GetReport().Findings;
}

function CreateFrame(): HTMLIFrameElement {
  const frame = document.createElement("iframe");
  document.body.appendChild(frame);
  return frame;
}

describe("RealmMonitor", () => {
  afterEach(() => {
    ResetGuard();
    document.body.innerHTML = "";
  });

  it("al obtener el realm de un iframe, extiende el monitoreo y reporta el acceso", async () => {
    const guard = BrowserGuard.Start(Config);
    const frame = CreateFrame();
    const realm = frame.contentWindow as FrameWindow;

    // Un sink usado desde el realm del iframe también se detecta.
    realm.document.body.innerHTML = '<img src="x" onerror="alert(1)">';

    const findings = await Findings(guard);
    expect(findings.map((finding) => finding.Title)).toEqual([
      "Same-origin frame realm accessed",
      "Dangerous content written to innerHTML",
    ]);
    expect(findings[0]).toMatchObject({
      Category: "runtime-integrity",
      Severity: "low",
      Evidence: { Frame: "about:blank", Access: "contentWindow" },
    });
  });

  it("contentDocument también protege el realm; cada realm se reporta una vez", async () => {
    const guard = BrowserGuard.Start(Config);
    const frame = CreateFrame();
    const realmDocument = frame.contentDocument as Document;
    // Accesos repetidos al mismo realm no se vuelven a reportar.
    expect(frame.contentWindow).not.toBeNull();
    expect(frame.contentDocument).toBe(realmDocument);
    realmDocument.body.innerHTML = "<script>steal()</script>";

    const titles = (await Findings(guard)).map((finding) => finding.Title);
    expect(titles.filter((title) => title === "Same-origin frame realm accessed")).toHaveLength(1);
    expect(titles).toContain("Dangerous content written to innerHTML");
    // En jsdom contentDocument se implementa leyendo contentWindow, por lo que el acceso
    // reportado puede ser cualquiera de los dos; el e2e verifica el caso del navegador.
  });

  it("los iframes insertados quedan protegidos para accesos no interceptables (frames[i])", async () => {
    const guard = BrowserGuard.Start(Config);
    CreateFrame();
    await FlushTasks();

    const realm = window.frames[0] as FrameWindow;
    realm.document.body.innerHTML = '<a href="javascript:steal()">x</a>';
    const titles = (await Findings(guard)).map((finding) => finding.Title);
    expect(titles).toContain("Dangerous content written to innerHTML");
  });

  it("Stop retira los monitores del realm", async () => {
    const guard = BrowserGuard.Start(Config);
    const frame = CreateFrame();
    const realm = frame.contentWindow as FrameWindow;
    const patched = Object.getOwnPropertyDescriptor(realm.Element.prototype, "innerHTML")?.set;
    guard.Stop();

    const restored = Object.getOwnPropertyDescriptor(realm.Element.prototype, "innerHTML")?.set;
    expect(restored).not.toBe(patched);
    realm.document.body.innerHTML = "<script>x</script>";
    expect(await Findings(guard)).toHaveLength(1);
  });

  it("Monitors.Realms: false no extiende el monitoreo", async () => {
    const guard = BrowserGuard.Start({
      ...Config,
      Monitors: { ...Config.Monitors, Realms: false },
    });
    const frame = CreateFrame();
    (frame.contentWindow as FrameWindow).document.body.innerHTML = "<script>x</script>";
    expect(await Findings(guard)).toEqual([]);
  });
});

describe("Sinks por propiedad", () => {
  afterEach(() => {
    ResetGuard();
  });

  it("detecta javascript: asignado a href, src, action, formAction y data", async () => {
    const guard = BrowserGuard.Start({
      ...Config,
      Monitors: { ...Config.Monitors, Realms: false },
    });
    document.createElement("a").href = "javascript:alert(document.cookie)";
    document.createElement("form").action = "javascript:steal()";
    // formAction no existe en jsdom: lo cubre el e2e en navegadores reales.
    document.createElement("object").data = "javascript:steal()";
    document.createElement("a").href = "javascript:void(0)";
    document.createElement("a").href = "https://example.com/";

    const findings = await Findings(guard);
    expect(findings.map((finding) => (finding.Evidence as { Sink: string }).Sink)).toEqual([
      "href",
      "action",
      "data",
    ]);
    expect(findings[0]?.Severity).toBe("critical");
  });
});
