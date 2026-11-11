import { useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";

export default function ErrorPage({ notFound = false }) {
  const navigate = useNavigate();
  const location = useLocation();
  const message = notFound
    ? "That page doesn't exist."
    : location.state?.message ?? "Something went wrong.";

  useEffect(() => {
    document.title = notFound ? "Page not found" : "Something went wrong";
  }, [notFound]);

  const goBack = () => (location.key === "default" ? navigate("/") : navigate(-1));

  return (
    <main className="page error-page" role="alert">
        <div className="error_ring">
          <h1>{notFound ? "404" : "Something went wrong"}</h1>
          <p className="error-message">{message}</p>
          <button type="button" className="error-back" onClick={goBack}>
            Go back
          </button>
      </div>
    </main>
  );
}