import Icon from "./Icon";

// Centred card used by the log in, sign up, password and email pages.
export default function AuthCard({ icon = "lock", title, subtitle, children, footer }) {
  return (
    <div className="fade-up mx-auto w-full max-w-md">
      <div className="card p-6 sm:p-8">
        <span className="flex h-12 w-12 items-center justify-center rounded-2xl bg-accent-soft text-accent">
          <Icon name={icon} className="h-6 w-6" />
        </span>
        <h1 className="mt-5 text-2xl font-bold tracking-tight text-fg sm:text-3xl">{title}</h1>
        {subtitle && <p className="mt-2 text-muted">{subtitle}</p>}
        {children}
      </div>
      {footer && <p className="mt-5 text-center text-muted">{footer}</p>}
    </div>
  );
}
