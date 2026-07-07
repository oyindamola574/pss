// pss/frontend/src/components/TaskBoard.tsx
import { useState } from "react";
import { MessageSquare, CheckCircle } from "lucide-react";
import type { SecurityTask, ScanReport } from "../types";

interface Props {
  tasks: SecurityTask[];
  selectedTask: SecurityTask | null;
  onSelectTask: (t: SecurityTask) => void;
  onUpdateStatus: (id: string, status: SecurityTask["status"]) => void;
  onAddComment: (id: string, user: string, text: string) => void;
  userName: string;
  onViewReport: (report: ScanReport) => void;
}

const COLUMNS: SecurityTask["status"][] = ["Pending", "In Progress", "Review", "Completed"];

const SEV_BADGE: Record<string, string> = {
  CRITICAL: "bg-red-950/20 text-red-400 border-red-900/30",
  WARNING:  "bg-amber-950/20 text-amber-400 border-amber-900/30",
  SAFE:     "bg-emerald-950/20 text-emerald-400 border-emerald-900/30",
};

export default function TaskBoard({ tasks, selectedTask, onSelectTask, onUpdateStatus, onAddComment, userName, onViewReport }: Props) {
  const [commentText, setCommentText] = useState("");

  const handleComment = () => {
    if (!selectedTask || !commentText.trim()) return;
    onAddComment(selectedTask.id, userName, commentText);
    setCommentText("");
  };

  const fetchAndViewReport = async (task: SecurityTask) => {
    try {
      const res = await fetch(task.reportUrl);
      if (res.ok) { const r = await res.json(); onViewReport(r); }
    } catch { /* ignore */ }
  };

  return (
    <div className="glass rounded-2xl p-5 flex flex-col gap-5 shadow-xl">
      <h2 className="text-sm font-bold text-white border-b border-white/5 pb-2">
        Collaborative Audit Sprint Board
      </h2>

      {/* Kanban columns */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {COLUMNS.map(col => {
          const colTasks = tasks.filter(t => t.status === col);
          return (
            <div key={col} className="bg-[#0d1525] p-3 rounded-xl border border-white/5 flex flex-col gap-2 min-h-[140px]">
              <div className="flex justify-between items-center border-b border-white/5 pb-1.5 mb-1">
                <span className="text-[9px] font-extrabold uppercase tracking-widest text-gray-400">{col}</span>
                <span className="text-[9px] bg-[#090d16] px-1.5 py-0.5 rounded text-gray-500 font-bold">{colTasks.length}</span>
              </div>
              {colTasks.map(task => (
                <div key={task.id}
                  onClick={() => onSelectTask(task)}
                  className={`p-2.5 rounded-lg border cursor-pointer transition-all ${
                    selectedTask?.id === task.id
                      ? "bg-[#1a2540] border-purple-500"
                      : "bg-[#090d16] border-white/5 hover:border-white/15"
                  }`}>
                  <div className="flex justify-between items-center gap-1 mb-1">
                    <span className={`text-[8px] font-extrabold px-1.5 py-0.5 rounded border uppercase ${SEV_BADGE[task.severity] ?? ""}`}>
                      {task.severity}
                    </span>
                    <span className="text-[8px] text-gray-500 font-mono">{task.riskScore}%</span>
                  </div>
                  <p className="text-[10px] font-bold text-white truncate leading-tight">{task.title}</p>
                  <p className="text-[9px] text-gray-600 font-mono mt-0.5 truncate">{task.targetAddress.slice(0, 10)}…</p>
                </div>
              ))}
            </div>
          );
        })}
      </div>

      {/* Selected task detail */}
      {selectedTask && (
        <div className="bg-[#0d1525] p-4 rounded-xl border border-white/5 flex flex-col gap-3">
          <div className="flex justify-between items-start flex-wrap gap-2">
            <div>
              <h3 className="text-sm font-bold text-white">{selectedTask.title}</h3>
              <p className="text-[10px] text-gray-500 font-mono mt-0.5">{selectedTask.targetAddress}</p>
            </div>
            <div className="flex gap-2 flex-wrap">
              {selectedTask.status !== "Completed" && (
                <button onClick={() => onUpdateStatus(selectedTask.id, "Completed")}
                  className="flex items-center gap-1.5 bg-emerald-700 hover:bg-emerald-600 text-[10px] font-bold text-white px-3 py-1.5 rounded-lg transition-colors">
                  <CheckCircle className="w-3.5 h-3.5" /> Close
                </button>
              )}
              {selectedTask.status === "Pending" && (
                <button onClick={() => onUpdateStatus(selectedTask.id, "In Progress")}
                  className="bg-blue-700 hover:bg-blue-600 text-[10px] font-bold text-white px-3 py-1.5 rounded-lg transition-colors">
                  Start
                </button>
              )}
              {selectedTask.status === "In Progress" && (
                <button onClick={() => onUpdateStatus(selectedTask.id, "Review")}
                  className="bg-amber-600 hover:bg-amber-500 text-[10px] font-bold text-white px-3 py-1.5 rounded-lg transition-colors">
                  Review
                </button>
              )}
              <button onClick={() => fetchAndViewReport(selectedTask)}
                className="bg-purple-700 hover:bg-purple-600 text-[10px] font-bold text-white px-3 py-1.5 rounded-lg transition-colors">
                View Report
              </button>
            </div>
          </div>

          {/* Comments */}
          <div className="flex flex-col gap-2 mt-1">
            <p className="text-[10px] text-gray-400 font-bold uppercase tracking-wider flex items-center gap-1">
              <MessageSquare className="w-3.5 h-3.5 text-blue-400" /> Logs ({selectedTask.comments.length})
            </p>
            <div className="flex flex-col gap-1.5 max-h-36 overflow-y-auto pr-1">
              {selectedTask.comments.map(c => (
                <div key={c.id} className="bg-[#090d16] p-2.5 rounded-lg border border-white/5 text-[10px]">
                  <div className="flex justify-between mb-0.5">
                    <span className="text-blue-400 font-bold">{c.user}</span>
                    <span className="text-gray-600 font-mono">{new Date(c.createdAt).toLocaleTimeString()}</span>
                  </div>
                  <p className="text-gray-300">{c.text}</p>
                </div>
              ))}
            </div>
            <div className="flex gap-2 mt-1">
              <input type="text" value={commentText}
                onChange={e => setCommentText(e.target.value)}
                onKeyDown={e => e.key === "Enter" && handleComment()}
                placeholder="Add audit log entry…"
                className="flex-1 bg-[#090d16] border border-white/10 rounded-lg px-3 py-1.5 text-[10px] text-white placeholder-gray-600 focus:outline-none focus:border-purple-500"
              />
              <button onClick={handleComment}
                className="bg-[#1e3a8a] hover:bg-blue-700 text-[10px] font-bold text-white px-3 py-1.5 rounded-lg transition-colors">
                Log
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
