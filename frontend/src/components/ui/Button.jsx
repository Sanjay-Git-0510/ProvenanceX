import { Link } from "react-router-dom";

/** Pill button. Pass `to` for an in-app link. */
export default function Button({
  to,
  variant = "primary",
  size,
  icon: Icon,
  loading = false,
  disabled = false,
  type = "button",
  className = "",
  children,
  ...rest
}) {
  const classes = ["button", `button--${variant}`, size && `button--${size}`, className]
    .filter(Boolean)
    .join(" ");
  const content = (
    <>
      {Icon ? <Icon size={16} aria-hidden="true" /> : null}
      {children}
    </>
  );

  if (to) {
    return (
      <Link className={classes} to={to} {...rest}>
        {content}
      </Link>
    );
  }
  return (
    <button
      className={classes}
      type={type}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      {...rest}
    >
      {content}
    </button>
  );
}
