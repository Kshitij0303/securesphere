export default function ErrorBox({ message }) {
  if (!message) return null;
  return (
    <p role="alert" className="mt-4 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-red-800">
      {message}
    </p>
  );
}