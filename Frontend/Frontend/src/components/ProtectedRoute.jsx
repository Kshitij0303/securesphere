import { Navigate, useLocation } from "react-router-dom";

// Sends visitors who are not logged in to the login page.
export default function ProtectedRoute({ loggedIn, children }) {
  const location = useLocation();
  if (!loggedIn) return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  return children;
}