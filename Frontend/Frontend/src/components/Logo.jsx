// Shield mark + name. Drawn as text (not the logo image) so it stays readable in both light and dark mode.
export default function Logo({ compact = false }) {
  return (
    <span className="flex items-center gap-2">
      <img src="/apple-touch-icon.png" alt="SecureSphere" width="36" height="36" className="h-9 w-9" />
      {!compact && (
        <span aria-hidden="true" className="text-xl font-extrabold tracking-tight">
          <span className="text-fg">Secure</span>
          <span className="text-accent">Sphere</span>
        </span>
      )}
    </span>
  );
}
