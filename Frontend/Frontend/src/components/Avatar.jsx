// Round badge with the first letter of the user's name.
export default function Avatar({ name, size = "h-9 w-9 text-base" }) {
  const initial = (name || "?").trim().charAt(0).toUpperCase() || "?";
  return (
    <span
      aria-hidden="true"
      className={`flex shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-teal-500 to-cyan-700 font-semibold text-white ${size}`}
    >
      {initial}
    </span>
  );
}
