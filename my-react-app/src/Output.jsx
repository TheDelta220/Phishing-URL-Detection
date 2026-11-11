import { useEffect, useState } from "react";
import scatter from "./assets/scatter.png";
import confusionMatrix from "./assets/confusion-matrix.png";
import "./Output.css";
import { SessionHistory, UrlFeatures } from "./ResultCharts.jsx";

const CX = 200;
const CY = 200;
const R = 150;
const START = 135;
const SWEEP = 270; 


const point = (deg, r) => {
  const a = (deg * Math.PI) / 180;
  return [CX + r * Math.cos(a), CY + r * Math.sin(a)];
};

const [x1, y1] = point(START, R);
const [x2, y2] = point(START + SWEEP, R);
const ARC = `M ${x1} ${y1} A ${R} ${R} 0 1 1 ${x2} ${y2}`;
const TICKS = [0, 25, 50, 75, 100];

export default function Output({ result, onBack }) {

  const score = Math.round((1 - result.phishing_probability) * 100);

  const [shown, setShown] = useState(0);
  useEffect(() => {
    const t = setTimeout(() => setShown(score), 50);
    return () => clearTimeout(t);
  }, [score]);

  const needleAngle = START + (SWEEP * shown) / 100;
  const isPhishing = result.verdict === "phishing";

  return (
    <div className="output-page">
      <svg className="output" viewBox="0 0 400 340" role="img" aria-label={`Trust score ${score} out of 100`}>
        <defs>
          <linearGradient id="arcGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" style={{ stopColor: "var(--orange)" }} />
            <stop offset="1" style={{ stopColor: "var(--red)" }} />
          </linearGradient>
          <linearGradient id="needleGrad" gradientUnits="userSpaceOnUse" x1={CX + 25} y1="0" x2={CX + 92} y2="0">
            <stop offset="0" stopColor="#fff" stopOpacity="0" />
            <stop offset="1" stopColor="#fff" stopOpacity="0.85" />
          </linearGradient>
        </defs>

        <path className="output-track" d={ARC} pathLength="100" />
        <path
          className="output-fill"
          d={ARC}
          pathLength="100"
          stroke="url(#arcGrad)"
          style={{ strokeDasharray: `${shown} 100` }}
        />

        {TICKS.map((v) => {
          const [tx, ty] = point(START + (SWEEP * v) / 100, R - 40);
          return (
            <text
              key={v}
              x={tx}
              y={ty}
              textAnchor="middle"
              dominantBaseline="central"
              className={`output-tick ${v <= shown ? "on" : ""}`}
            >
              {v}
            </text>
          );
        })}

        <g
          className="output-needle"
          style={{ transform: `rotate(${needleAngle}deg)`, transformOrigin: `${CX}px ${CY}px` }}
        >
          <polygon
            fill="url(#needleGrad)"
            points={`${CX + 25},${CY - 16} ${CX + 92},${CY - 7} ${CX + 92},${CY + 7} ${CX + 25},${CY + 16}`}
          />
        </g>

        <text x={CX} y="272" textAnchor="middle" className="output-number">
          {score}
        </text>
        <text x={CX} y="305" textAnchor="middle" className="output-label">
          TRUST SCORE
        </text>
      </svg>

      <p className={`output-verdict ${isPhishing ? "phishing" : "legit"}`}>
        {isPhishing ? "Phishing" : "Looks legitimate"}
      </p>
      <p className="output-url">{result.url}</p>

      {result.signals.length > 0 && (
        <ul className="output-signals">
          {result.signals.map((s) => (
            <li key={s.id}>
              <strong>{s.label}:</strong> {s.detail}
            </li>
          ))}
        </ul>
      )}

      <button type="button" className="output-back" onClick={onBack}>
        Check another URL
      </button>
      <section className="output-insights" aria-labelledby="insights-h">
        <h2 id="insights-h">About this check</h2>
          <div className="output-insights-graphs">
          <UrlFeatures url={result.url} />
          <SessionHistory currentId={result.id} />
          </div>
      </section>
      <section className="output-graphs">
        <h2 className="output-graphs-title">How the model performs and its data set</h2>
        <div className="output_graphs">
        <figure className="output-graph">
          <img
            src={scatter}
            alt="Scatter plot of URL length against special character count, coloured by class"
          />
          <figcaption>URL length vs special character count, by class</figcaption>
        </figure>

        <figure className="output-graph">
          <img
            src={confusionMatrix}
            alt="Confusion matrix of true labels against predicted labels"
          />
          <figcaption>Confusion matrix: true vs predicted labels</figcaption>
        </figure>
        </div>
      </section>
    </div>
  );
}