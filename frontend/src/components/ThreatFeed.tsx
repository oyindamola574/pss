// pss/frontend/src/components/ThreatFeed.tsx
import React, { useState } from "react";
import { PlusCircle, Rss } from "lucide-react";

interface Article {
  id: string;
  headline: string;
  content: string;
  severity: "INFO" | "WARNING" | "CRITICAL";
  threatType: string;
  publishedAt: string;
}

interface Props {
  articles: Article[];
  onArticleAdded: () => void;
}

const SEV: Record<string, string> = {
  CRITICAL: "bg-red-950/20 text-red-400 border-red-900/30",
  WARNING:  "bg-amber-950/20 text-amber-400 border-amber-900/30",
  INFO:     "bg-blue-950/20 text-blue-400 border-blue-900/30",
};

export default function ThreatFeed({ articles, onArticleAdded }: Props) {
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ headline: "", content: "", severity: "INFO" as Article["severity"], threatType: "GENERAL" });

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    await fetch("/api/context/articles", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(form),
    });
    setForm({ headline: "", content: "", severity: "INFO", threatType: "GENERAL" });
    setShowForm(false);
    onArticleAdded();
  };

  return (
    <div className="glass rounded-2xl p-5 flex flex-col gap-4 shadow-xl">
      <div className="flex items-center justify-between border-b border-white/5 pb-2">
        <h2 className="text-sm font-bold text-white flex items-center gap-2">
          <Rss className="w-4 h-4 text-amber-400" /> Sentinel Threat Feed
        </h2>
        <button onClick={() => setShowForm(!showForm)}
          className="text-[10px] text-purple-400 hover:text-purple-300 flex items-center gap-1 font-semibold">
          <PlusCircle className="w-3.5 h-3.5" /> Add
        </button>
      </div>

      {showForm && (
        <form onSubmit={submit} className="bg-[#0d1525] p-3.5 rounded-xl border border-white/5 flex flex-col gap-2.5">
          <input required placeholder="Headline" value={form.headline}
            onChange={e => setForm({ ...form, headline: e.target.value })}
            className="bg-[#090d16] border border-white/5 rounded-lg px-3 py-1.5 text-xs text-white outline-none focus:border-purple-500" />
          <textarea required rows={2} placeholder="Description…" value={form.content}
            onChange={e => setForm({ ...form, content: e.target.value })}
            className="bg-[#090d16] border border-white/5 rounded-lg px-3 py-1.5 text-xs text-white outline-none focus:border-purple-500 resize-none" />
          <div className="grid grid-cols-2 gap-2">
            <select value={form.severity} onChange={e => setForm({ ...form, severity: e.target.value as any })}
              className="bg-[#090d16] border border-white/5 rounded-lg px-2 py-1.5 text-xs text-gray-200 outline-none">
              <option value="INFO">Info</option>
              <option value="WARNING">Warning</option>
              <option value="CRITICAL">Critical</option>
            </select>
            <button type="submit" className="bg-purple-600 hover:bg-purple-500 text-xs font-bold text-white rounded-lg transition-colors">
              Publish
            </button>
          </div>
        </form>
      )}

      <div className="flex flex-col gap-3 overflow-y-auto max-h-80 pr-1">
        {articles.map(art => (
          <div key={art.id} className="bg-[#0d1525]/60 p-3 rounded-xl border border-white/5 hover:border-white/10 transition-all flex flex-col gap-1.5">
            <div className="flex justify-between items-center gap-2">
              <span className={`text-[8px] font-extrabold px-2 py-0.5 rounded border uppercase ${SEV[art.severity] ?? ""}`}>
                {art.severity}
              </span>
              <span className="text-[9px] text-gray-500 font-mono">{art.threatType}</span>
            </div>
            <h3 className="text-[11px] font-bold text-white leading-tight">{art.headline}</h3>
            <p className="text-[10px] text-gray-400 leading-normal line-clamp-2">{art.content}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
