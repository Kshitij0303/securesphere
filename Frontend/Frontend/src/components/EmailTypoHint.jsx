import { suggestEmail } from "../emailTypo";

// "Did you mean name@gmail.com?" under an email field; clicking it fixes the address.
export default function EmailTypoHint({ email, onAccept }) {
  const suggestion = suggestEmail(email);
  if (!suggestion) return null;
  return (
    <p className="mt-1.5 text-sm text-warn">
      Did you mean{" "}
      <button type="button" onClick={() => onAccept(suggestion)} className="font-semibold underline">
        {suggestion}
      </button>
      ?
    </p>
  );
}
