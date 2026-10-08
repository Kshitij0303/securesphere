import Icon from "./Icon";

export default function ErrorBox({ message }) {
  if (!message) return null;
  return (
    <p role="alert" className="notice mt-4 flex items-start gap-2 border-bad/30 bg-bad-soft text-fg">
      <Icon name="alert" className="mt-0.5 h-4 w-4 shrink-0 text-bad" />
      <span>{message}</span>
    </p>
  );
}
