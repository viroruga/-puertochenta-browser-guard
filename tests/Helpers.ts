import { BrowserGuard } from "../src/BrowserGuard";

/**
 * Espera a que se procesen las microtasks pendientes (detección diferida).
 */
export async function FlushMicrotasks(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
}

/**
 * Espera una vuelta completa del event loop (macrotask).
 */
export async function FlushTasks(): Promise<void> {
  await new Promise<void>((resolve) => {
    setTimeout(resolve, 0);
  });
}

/**
 * Garantiza que no quede ninguna instancia activa entre tests.
 */
export function ResetGuard(): void {
  BrowserGuard.Stop();
}
