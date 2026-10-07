import type { ConsoleNoticeText } from "../Types/BrowserGuardConfig";

/**
 * Marca global para mostrar el aviso una sola vez por página, aunque BrowserGuard
 * se detenga y reinicie o el módulo se reevalúe (HMR).
 */
const NoticeShownKey = Symbol.for("puertochenta.browser-guard.notice-shown");

type NoticeGlobal = typeof globalThis & { [NoticeShownKey]?: boolean };

const TitleStyle =
  "font-size:16px;font-weight:bold;color:#fff;background:#1f3a8a;padding:6px 10px;border-radius:4px";
const MessageStyle = "font-size:13px;line-height:1.5";

/**
 * Muestra en consola el aviso de monitoreo (modo "notice").
 * No revela hallazgos, configuración ni detalles internos: solo informa que la
 * página está protegida. Retorna true si el aviso se imprimió.
 */
export function ShowConsoleNotice(
  notice: ConsoleNoticeText,
  output: Pick<Console, "info"> = console,
): boolean {
  const global = globalThis as NoticeGlobal;
  if (global[NoticeShownKey] === true) {
    return false;
  }
  global[NoticeShownKey] = true;
  // "%" se escapa para que el texto no se interprete como directiva de formato.
  output.info(`%c${notice.Title.replaceAll("%", "%%")}`, TitleStyle);
  output.info(`%c${notice.Message.replaceAll("%", "%%")}`, MessageStyle);
  return true;
}
