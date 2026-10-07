/** Atributo que marca un elemento protegido cuyo contenido fue retirado. */
export const ShieldedAttribute = "data-guard-shielded";

/**
 * Retira del DOM el contenido de los elementos protegidos cuando la sesión se
 * considera un bot.
 *
 * Por qué retirar y no ocultar con CSS: un scraper lee el DOM (textContent,
 * innerHTML), no lo que se ve en pantalla. El contenido se mueve a un fragmento en
 * memoria, fuera del documento, y se repone intacto con Restore().
 *
 * Mientras está activo, un MutationObserver protege también los elementos que se
 * inserten después y el contenido que se vuelva a agregar dentro de un elemento
 * protegido (p. ej. por un re-render).
 *
 * Advertencia para frameworks (React, Vue, Angular): mover nodos administrados por
 * el framework puede desincronizar su render. Para contenido renderizado por el
 * framework es preferible consultar GetBotAssessment() / el evento "Bot" y no
 * renderizar los datos sensibles.
 */
export class ContentShield {
  private readonly Stash = new Map<Element, DocumentFragment>();
  private readonly Placeholders = new WeakSet<Node>();
  private Observer: MutationObserver | null = null;

  public constructor(
    private readonly Window: Window & typeof globalThis,
    private readonly Selector: string,
    private readonly Placeholder: string,
  ) {}

  public IsActive(): boolean {
    return this.Observer !== null;
  }

  public get ShieldedCount(): number {
    return this.Stash.size;
  }

  /** Protege los elementos actuales y los que aparezcan después. */
  public Activate(): void {
    if (this.Observer) {
      return;
    }
    const document = this.Window.document;
    for (const element of document.querySelectorAll(this.Selector)) {
      this.Shield(element);
    }
    this.Observer = new this.Window.MutationObserver((records) => {
      this.OnMutations(records);
    });
    this.Observer.observe(document, { childList: true, subtree: true });
  }

  /** Repone todo el contenido retirado y deja de observar. */
  public Restore(): void {
    this.Observer?.disconnect();
    this.Observer = null;
    for (const [element, fragment] of this.Stash) {
      for (const child of [...element.childNodes]) {
        if (this.Placeholders.has(child)) {
          child.remove();
        }
      }
      element.appendChild(fragment);
      element.removeAttribute(ShieldedAttribute);
    }
    this.Stash.clear();
  }

  private OnMutations(records: readonly MutationRecord[]): void {
    for (const record of records) {
      const target = record.target as Element;
      if (this.Stash.has(target)) {
        // Contenido agregado dentro de un elemento ya protegido.
        this.MoveToStash(target, [...record.addedNodes]);
        continue;
      }
      for (const node of record.addedNodes) {
        if (node.nodeType !== 1 || this.Placeholders.has(node)) {
          continue;
        }
        const element = node as Element;
        if (element.matches(this.Selector)) {
          this.Shield(element);
        }
        for (const nested of element.querySelectorAll(this.Selector)) {
          this.Shield(nested);
        }
      }
    }
  }

  private Shield(element: Element): void {
    if (this.Stash.has(element)) {
      return;
    }
    this.Stash.set(element, this.Window.document.createDocumentFragment());
    this.MoveToStash(element, [...element.childNodes]);
    const placeholder = this.Window.document.createTextNode(this.Placeholder);
    this.Placeholders.add(placeholder);
    element.appendChild(placeholder);
    element.setAttribute(ShieldedAttribute, "");
  }

  private MoveToStash(element: Element, nodes: readonly Node[]): void {
    const fragment = this.Stash.get(element);
    if (!fragment) {
      return;
    }
    for (const node of nodes) {
      if (!this.Placeholders.has(node) && node.parentNode === element) {
        fragment.appendChild(node);
      }
    }
  }
}
