import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatRelativeTime(date: Date | string): string {
  const now = new Date();
  const target = new Date(date);
  const diffMs = now.getTime() - target.getTime();
  const diffSecs = Math.floor(diffMs / 1000);
  const diffMins = Math.floor(diffSecs / 60);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (diffSecs < 60) {
    return `${diffSecs}s ago`;
  } else if (diffMins < 60) {
    return `${diffMins}m ago`;
  } else if (diffHours < 24) {
    return `${diffHours}h ago`;
  } else {
    return `${diffDays}d ago`;
  }
}

export function getStatusColor(status: string): string {
  switch (status.toLowerCase()) {
    case 'compromised':
    case 'captured':
    case 'completed':
    case 'online':
    case 'active':
      return 'text-green-400 bg-green-500/20';
    case 'in-progress':
    case 'pending':
    case 'busy':
      return 'text-amber-400 bg-amber-500/20';
    case 'target':
    case 'failed':
    case 'error':
    case 'offline':
      return 'text-red-400 bg-red-500/20';
    case 'inactive':
    default:
      return 'text-slate-400 bg-slate-500/20';
  }
}

export function getStatusIcon(status: string): string {
  switch (status.toLowerCase()) {
    case 'compromised':
    case 'captured':
      return 'fa-check-circle';
    case 'in-progress':
    case 'busy':
      return 'fa-spinner fa-spin';
    case 'target':
      return 'fa-crosshairs';
    case 'failed':
    case 'error':
      return 'fa-exclamation-triangle';
    case 'online':
    case 'active':
      return 'fa-circle';
    case 'offline':
    case 'inactive':
      return 'fa-circle';
    default:
      return 'fa-circle';
  }
}

export function calculateCompletionPercentage(captured: number, total: number): number {
  return total > 0 ? Math.round((captured / total) * 100) : 0;
}
