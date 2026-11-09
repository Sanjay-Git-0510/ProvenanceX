import { useEffect, useId, useRef } from "react";
import { createPortal } from "react-dom";
import { X } from "lucide-react";

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

function trapTab(event, panel) {
  const items = [...panel.querySelectorAll(FOCUSABLE)];
  if (items.length === 0) {
    event.preventDefault();
    return;
  }
  const first = items[0];
  const last = items[items.length - 1];
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first.focus();
  }
}

/** Dialog with a frosted backdrop and a solid panel. Focus is trapped and then restored. */
export default function Modal({ open, onClose, title, footer, children }) {
  const titleId = useId();
  const panelRef = useRef(null);
  const closeRef = useRef(onClose);

  useEffect(() => {
    closeRef.current = onClose;
  }, [onClose]);

  useEffect(() => {
    if (!open) return undefined;
    const previousFocus = document.activeElement;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    panelRef.current?.focus();

    function onKeyDown(event) {
      if (event.key === "Escape") closeRef.current();
      if (event.key === "Tab" && panelRef.current) trapTab(event, panelRef.current);
    }
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      document.body.style.overflow = previousOverflow;
      previousFocus?.focus?.();
    };
  }, [open]);

  if (!open) return null;
  return createPortal(
    <div
      className="modal-backdrop"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div
        className="modal"
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
      >
        <button type="button" className="modal__close" aria-label="Close" onClick={onClose}>
          <X size={16} aria-hidden="true" />
        </button>
        <h2 className="modal__title" id={titleId}>
          {title}
        </h2>
        {children}
        {footer ? <div className="modal__footer">{footer}</div> : null}
      </div>
    </div>,
    document.body,
  );
}
