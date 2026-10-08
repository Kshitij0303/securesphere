import Icon from "./Icon";

// Friendly placeholder for lists that have nothing in them yet.
export default function EmptyState({ icon, title, text, children }) {
  return (
    <div className="card fade-up flex flex-col items-center px-6 py-12 text-center">
      <span className="flex h-12 w-12 items-center justify-center rounded-2xl bg-accent-soft text-accent">
        <Icon name={icon} className="h-6 w-6" />
      </span>
      <p className="mt-4 font-semibold text-fg">{title}</p>
      {text && <p className="mt-1 max-w-md text-muted">{text}</p>}
      {children && <div className="mt-5">{children}</div>}
    </div>
  );
}
