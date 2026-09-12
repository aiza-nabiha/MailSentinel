export default function RiskGauge({ score, level }) {
  const color = level === "High" ? "var(--high)" : level === "Medium" ? "var(--medium)" : "var(--safe)";
  const circumference = 452;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div className="gauge-wrap">
      <svg viewBox="0 0 168 168">
        <circle className="gauge-track" cx="84" cy="84" r="72" />
        <circle
          className="gauge-fill"
          cx="84" cy="84" r="72"
          stroke={color}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ filter: `drop-shadow(0 0 10px ${color})` }}
        />
      </svg>
      <div className="gauge-center">
        <div className="gauge-score">{score}</div>
        <div className="gauge-max">/ 100</div>
      </div>
    </div>
  );
}