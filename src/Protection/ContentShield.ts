/**
 * Atributo que marca un elemento protegido cuyo contenido fue retirado (se quita al
 * restaurar). Sirve para identificar esos elementos desde CSS o desde pruebas.
 */
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
 *
 * Lo activa y restaura AntiScrapingController según el veredicto (ProtectAt).
 */
export class ContentShield {
  /** Contenido retirado de cada elemento protegido, en un fragmento fuera del documento. */
  private readonly Stash = new Map<Element, DocumentFragment>();
  /**
   * Nodos de texto placeholder insertados por el shield: no se retiran ni se tratan
   * como contenido nuevo. WeakSet para no retenerlos si la página los elimina.
   */
  private readonly Placeholders = new WeakSet<Node>();
  /** Presente mientras el shield está activo. */
  private Observer: MutationObserver | null = null;

  public constructor(
    private readonly Window: Window & typeof globalThis,
    private readonly Selector: string,
    private readonly Placeholder: string,
  ) {}

  /** Indica si el shield está activo (protegiendo y observando el DOM). */
  public IsActive(): boolean {
    return this.Observer !== null;
  }

  /** Cantidad de elementos cuyo contenido está retirado. */
  public get ShieldedCount(): number {
    return this.Stash.size;
  }

  /** Protege los elementos actuales y los que aparezcan después. Es idempotente. */
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
      // Solo se quitan los placeholders propios: lo que la página haya agregado mientras
      // tanto (y no fue retirado) se conserva.
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

  /**
   * Reacciona a inserciones: retira contenido nuevo dentro de elementos ya protegidos y
   * protege los elementos (o descendientes) que coincidan con el selector.
   */
  private OnMutations(records: readonly MutationRecord[]): void {
    for (const record of records) {
      const target = record.target as Element;
      if (this.Stash.has(target)) {
        // Contenido agregado dentro de un elemento ya protegido.
        this.MoveToStash(target, [...record.addedNodes]);
        continue;
      }
      for (const node of record.addedNodes) {
        // 1 = ELEMENT_NODE (constante numérica: Node puede no existir en este realm).
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

  /**
   * Retira el contenido de un elemento y deja el placeholder como nodo de texto (nunca
   * HTML, así el texto configurado no puede inyectar marcado).
   */
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

  /** Mueve al fragmento del elemento los nodos indicados, conservando su orden. */
  private MoveToStash(element: Element, nodes: readonly Node[]): void {
    const fragment = this.Stash.get(element);
    if (!fragment) {
      return;
    }
    for (const node of nodes) {
      // parentNode === element: el registro de mutación puede estar desactualizado (el
      // nodo ya se movió o eliminó); solo se retira lo que sigue dentro del elemento.
      if (!this.Placeholders.has(node) && node.parentNode === element) {
        fragment.appendChild(node);
      }
    }
  }
}
