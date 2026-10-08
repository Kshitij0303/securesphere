import Icon from "./Icon";

// Title block at the top of each signed-in page.
export default function PageHeader({ icon, title, children, action }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-4">
      <div className="flex items-start gap-4">
        {icon && (
          <span className="hidden h-12 w-12 shrink-0 items-center justify-center rounded-2xl bg-accent-soft text-accent sm:flex">
            <Icon name={icon} className="h-6 w-6" />
          </span>
        )}
        <div>
          <h1 className="page-title">{title}</h1>
          {children && <div className="page-lead">{children}</div>}
        </div>
      </div>
      {action}
    </div>
  );
}
