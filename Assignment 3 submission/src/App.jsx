/*======================================================================
IMPORTS
=======================================================================*/
import { useState } from "react";
import { ErrorBoundary } from "react-error-boundary";
import { Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import Output from "./Output.jsx";
import ErrorPage from "./Errors.jsx";
import "./App.css";
import { getSessionId } from "./session.js";
/*======================================================================
cleaning the URL before anything is sent to the backend
=======================================================================*/
function cleanURL(value) {
  const trimmed = value.trim();
  if (!trimmed) return null;
  const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  try {
    const url = new URL(withScheme);
    return url.hostname.includes(".") ? url.href : null;
  } catch {
    return null;
  }
}
/*======================================================================
MAIN FUNCTION
=======================================================================*/
function Home() {
  const navigate = useNavigate();
  const [input, setInput] = useState("");
  const [status, setStatus] = useState("");
  //when Go is pushed:
  const Go = async (e) => {
    //prevent page reload
    e.preventDefault();
    //checks if the URL is a URL, if not, it will return an error message
    if (!cleanURL(input)) {
      setStatus("Enter a valid URL, like example.com");
      return;
    }
    setStatus("Checking...");
    //2 second delay
    await new Promise(resolve => setTimeout(resolve, 2000));
    try {
      const res = await fetch("http://localhost:8000/api/predict", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Session-ID": getSessionId(),
        },
        body: JSON.stringify({ url: input.trim() }),
      });
      const data = await res.json();

      if (res.status >= 500) {
        navigate("/error", {
          state: { message: data.error?.message ?? "The server had a problem." },
        });
        return;
      }

      if (!res.ok) {
        setStatus(data.error?.message ?? "Something went wrong.");
        return;
      }
      navigate("/result", { state: { result: data } });
    } catch {
      navigate("/error", {
        state: { message: "Can't reach the server. Is the backend running?" },
      });
    }
  };

  return (
    <div className="page">
      <nav className="topbar">
        <button type="button" className="nav-item">
          <svg viewBox="0 0 600 600" aria-hidden="true"> 
            <g transform="translate(200,530) scale(0.1,-0.1)">
              <path d="M2105 3780 c-269 -22 -547 -124 -770 -281 -114 -81 -282 -249 -362 -362 -126 -179 -214 -384 -259 -606 -24 -118 -26 -139 -21 -331 7 -276 40 -416 151 -645 220 -449 638 -763 1131 -847 102 -17 148 -19 305 -15 259 7 419 47 645 158 458 225 772 662 846 1177 17 122 6 412 -20 529 -72 325 -249 628 -485 835 -328 285 -736 422 -1161 388z m436 -118 c437 -103 787 -373 988 -762 66 -129 99 -221 133 -372 20 -88 23 -131 23 -293 0 -199 -14 -293 -66 -457 -33 -104 -133 -298 -200 -388 -228 -310 -529 -504 -909 -586 -133 -29 -430 -27 -568 4 -151 34 -243 67 -372 133 -388 200 -661 554 -761 988 -26 112 -37 384 -19 502 76 520 406 947 890 1151 96 41 197 70 315 92 117 22 429 15 546 -12z"/> 
              <path d="M2187 3464 c-3 -4 -7 -286 -7 -626 l0 -620 433 -434 c238 -239 439 -434 446 -434 15 0 61 45 61 61 0 6 -189 200 -420 432 l-420 420 0 601 0 601 -43 3 c-23 2 -46 0 -50 -4z"/> 
            </g> 
          </svg>
          HISTORY
        </button>
        <button type="button" className="nav-item">
          <svg viewBox="0 0 600 600" aria-hidden="true"> 
            <g transform="translate(0,300) scale(0.1,-0.1)" fill="#000000"> 
              <path fill="#ffffff" d="M3119 2163 c17 -18 36 -56 50 -103 12 -41 32 -106 43 -143 39 -132 134 -209 256 -209 98 0 140 25 272 162 94 99 120 120 143 120 28 0 253 -115 290 -147 24 -23 22 -64 -14 -215 -44 -186 -33 -263 49 -346 86 -85 163 -91 375 -30 138 40 150 41 175 27 30 -16 182 -252 182 -282 0 -31 -20 -58 -118 -162 -55 -58 -105 -121 -118 -150 -56 -119 -10 -272 101 -333 17 -10 99 -35 184 -57 129 -33 157 -44 172 -65 14 -20 18 -53 22 -173 5 -189 9 -184 -151 -233 -64 -19 -135 -42 -157 -50 -98 -34 -167 -135 -167 -242 0 -97 26 -141 163 -272 96 -93 119 -120 119 -143 0 -27 -116 -254 -147 -289 -23 -26 -70 -23 -213 13 -140 34 -209 35 -274 4 -87 -42 -146 -133 -146 -228 -1 -32 16 -109 42 -200 40 -138 41 -150 27 -175 -16 -30 -252 -182 -282 -182 -31 0 -59 20 -162 118 -58 55 -121 105 -150 118 -124 59 -286 4 -340 -116 -10 -23 -35 -105 -54 -182 -46 -182 -37 -175 -236 -181 l-149 -4 -27 26 c-15 15 -34 53 -43 86 -72 252 -94 290 -188 338 -43 22 -69 29 -116 29 -98 0 -140 -25 -272 -162 -133 -138 -137 -140 -234 -86 -34 18 -88 48 -121 66 -111 61 -112 61 -64 262 44 186 33 263 -49 346 -86 85 -163 91 -375 30 -138 -40 -150 -41 -175 -27 -29 16 -181 252 -182 282 0 31 20 58 118 162 55 58 105 121 118 150 48 101 22 231 -61 304 -49 43 -74 53 -220 86 -129 30 -169 45 -183 73 -5 9 -12 84 -14 165 -7 191 -12 183 165 237 73 22 151 50 175 62 81 40 134 130 134 228 0 96 -26 139 -162 270 -97 93 -120 120 -120 143 0 27 116 254 147 290 23 25 70 22 213 -14 183 -45 265 -33 348 49 85 86 91 163 30 375 -52 181 -54 176 87 264 144 90 158 97 189 89 15 -4 75 -52 134 -107 126 -119 179 -149 267 -149 99 1 184 50 227 134 11 21 35 102 54 180 23 92 42 148 55 161 17 17 37 21 142 26 67 3 137 6 155 7 25 2 41 -5 61 -25z"/> 
              <path transform="translate(0,-2950)" d="M2758 4220 c-382 -80 -690 -314 -865 -656 -94 -183 -133 -349 -133 -564 0 -218 39 -383 136 -570 123 -237 302 -415 540 -537 183 -94 349 -133 564 -133 212 0 377 38 560 130 347 174 590 500 664 889 21 109 21 333 0 442 -98 518 -485 905 -1003 1003 -117 22 -349 20 -463 -4z"/> 
            </g> 
          </svg>
          SETTINGS
        </button>
      </nav>

      <form className="main" onSubmit={Go}>
        <button type="submit" className="go" aria-label="Start test" disabled={status === "Checking..."}>
          GO
        </button>

        <div className="url-area">
          <input
            type="text"
            className="url-input"
            placeholder="Enter a URL, e.g. example.com"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            aria-label="URL to test"
            spellCheck="false"
            autoComplete="off"
          />
          <p className="status" role="status">
            {status}
          </p>
        </div>
      </form>
    </div>
  );
}
/*======================================================================
Goes to the results page
=======================================================================*/
function OutputRoute() {
  const navigate = useNavigate();
  const result = useLocation().state?.result;
  if (!result) return <Navigate to="/" replace />;
  return <Output result={result} onBack={() => navigate("/")} />;
}
export default function App() {
  const location = useLocation();
  return (
    <ErrorBoundary
      resetKeys={[location.pathname]}
      fallbackRender={({ error }) => (
        <Navigate to="/error" replace state={{ message: error.message }} />
      )}
    >
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/result" element={<OutputRoute />} />
        <Route path="/error" element={<ErrorPage />} />
        <Route path="*" element={<ErrorPage notFound />} />
      </Routes>
    </ErrorBoundary>
  );
}