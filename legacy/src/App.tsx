/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Lock,
  User,
  CreditCard,
  Send,
  LogOut,
  ArrowRight,
  ShieldCheck,
  CheckCircle2,
  AlertCircle,
  History,
  Mail,
  RefreshCw,
  Landmark,
  ArrowUpRight,
  ArrowDownLeft,
  Activity,
  ArrowLeft,
  Trash2,
  Key,
  Copy,
  Eye,
  EyeOff,
  Shield,
  Terminal,
  Brain,
  Network,
  X,
  AlertTriangle,
  ShieldAlert,
  Sparkles,
  ChevronRight,
  Layers,
  Search,
  Download,
  FileText,
  Building2,
} from 'lucide-react';

interface AuthUser {
  id: number;
  username: string;
  name: string;
  email: string;
  address?: string;
  role: string;
}

interface UserAccount {
  id: string;
  userId: number;
  accountNumber: string;
  type: string;
  balance: number;
  currency: string;
}

interface Transaction {
  id: string;
  accountId: string;
  fromUserId: number;
  toAccountNumber: string;
  amount: number;
  type: string;
  description: string;
  timestamp: string;
}

interface AuditEntry {
  id: string;
  timestamp: string;
  userId: number | null;
  username: string;
  sessionToken: string | null;
  action: string;
  narrative: string;
  method: string;
  endpoint: string;
  statusCode: number;
  ipAddress: string;
  metadata?: Record<string, any>;
}

interface AttackGraphStep {
  stepNumber: number;
  phase: string;
  title: string;
  description: string;
  actor: string;
  target: string;
  status: 'SUCCESS' | 'BLOCKED' | 'FLAGGED';
  timestamp: string;
}

interface AttackGraphNode {
  id: string;
  label: string;
  type: 'actor' | 'endpoint' | 'target' | 'impact';
  details: string;
}

interface AttackGraphEdge {
  from: string;
  to: string;
  label: string;
}

interface AlertExplanation {
  source: 'AI_GEMINI' | 'PREDEFINED_RULE';
  overview: string;
  rootCause: string;
  attackMechanics: string;
  businessImpact: string;
  remediation: string;
  generatedAt: string;
}

interface SecurityAlert {
  id: string;
  timestamp: string;
  alertType: 'POSSIBLE_IDOR_ATTACK' | 'POSSIBLE_BUSINESS_LOGIC_ATTACK' | 'RESOURCE_ENUMERATION_ATTACK' | 'SUSPICIOUS_AUTH_ANOMALY';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  title: string;
  summary: string;
  userId: number | null;
  username: string;
  endpoint: string;
  method: string;
  statusCode: number;
  attemptsCount: number;
  isCrossFunctional: boolean;
  affectedEndpoints: string[];
  explanation: AlertExplanation;
  attackGraph: {
    steps: AttackGraphStep[];
    nodes: AttackGraphNode[];
    edges: AttackGraphEdge[];
  };
}

export default function App() {
  // Session & Authentication state (Banking)
  const [token, setToken] = useState<string | null>(null);
  const [user, setUser] = useState<AuthUser | null>(null);
  const [account, setAccount] = useState<UserAccount | null>(null);
  const [transactions, setTransactions] = useState<Transaction[]>([]);

  // Navigation mode: 'banking' (bank portal) vs 'soc' (defense monitoring center)
  const [viewMode, setViewMode] = useState<'banking' | 'soc'>('banking');

  // Banking internal tab: 'transfer' | 'history' | 'email' | 'apikey'
  const [activeTab, setActiveTab] = useState<'transfer' | 'history' | 'email' | 'apikey'>('transfer');

  // SOC internal tab: 'audit' (standalone Tab 1) | 'alerts' (standalone Tab 2)
  const [socActiveTab, setSocActiveTab] = useState<'audit' | 'alerts'>('audit');

  // SOC Admin Session state
  const [socToken, setSocToken] = useState<string | null>(null);
  const [socUsername, setSocUsername] = useState('admin');
  const [socPassword, setSocPassword] = useState('admin');
  const [socLoginError, setSocLoginError] = useState<string | null>(null);
  const [isSocLoggingIn, setIsSocLoggingIn] = useState(false);

  // Bank Login form state
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loginError, setLoginError] = useState<string | null>(null);
  const [isLoggingIn, setIsLoggingIn] = useState(false);

  // Transfer form state
  const [transferTo, setTransferTo] = useState('');
  const [transferAmount, setTransferAmount] = useState('');
  const [transferDesc, setTransferDesc] = useState('');
  const [transferStatus, setTransferStatus] = useState<{ type: 'success' | 'error'; message: string } | null>(null);
  const [isTransferring, setIsTransferring] = useState(false);

  // Email update form state
  const [newEmail, setNewEmail] = useState('');
  const [emailStatus, setEmailStatus] = useState<{ type: 'success' | 'error'; message: string } | null>(null);
  const [isUpdatingEmail, setIsUpdatingEmail] = useState(false);

  // API Key Tab state
  const [apiKeyData, setApiKeyData] = useState<{ userId: number; name: string; username: string; apiKey: string } | null>(null);
  const [isFetchingKey, setIsFetchingKey] = useState(false);
  const [keyError, setKeyError] = useState<string | null>(null);
  const [showRawKey, setShowRawKey] = useState(false);
  const [copiedKey, setCopiedKey] = useState(false);

  // Audit Logs state (Old-school B&W Log)
  const [auditLogs, setAuditLogs] = useState<AuditEntry[]>([]);
  const [isRefreshingAudit, setIsRefreshingAudit] = useState(false);
  const [auditSearchQuery, setAuditSearchQuery] = useState('');
  const [isRefreshingHistory, setIsRefreshingHistory] = useState(false);

  // Security Alerts state
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [isRefreshingAlerts, setIsRefreshingAlerts] = useState(false);
  const [selectedAlertForExplain, setSelectedAlertForExplain] = useState<SecurityAlert | null>(null);
  const [selectedAlertForGraph, setSelectedAlertForGraph] = useState<SecurityAlert | null>(null);
  const [isLoadingExplanation, setIsLoadingExplanation] = useState(false);

  // Bank Statement Download state
  const [downloadedStatement, setDownloadedStatement] = useState<{
    statementId: string;
    generatedAt: string;
    period: string;
    bankName: string;
    bankAddress: string;
    accountHolder: {
      name: string;
      username: string;
      email: string;
      address: string;
      userId: number;
    };
    account: {
      accountNumber: string;
      type: string;
      balance: number;
      currency: string;
    };
    transactions: Transaction[];
    rawText?: string;
  } | null>(null);
  const [isDownloadingStatement, setIsDownloadingStatement] = useState(false);
  const [statementError, setStatementError] = useState<string | null>(null);

  // Download bank statement (vulnerable to account number IDOR parameter swap in Burp)
  const handleDownloadStatement = useCallback(async (accountNum: string) => {
    if (!token) return;
    setIsDownloadingStatement(true);
    setStatementError(null);
    try {
      const res = await fetch(`/api/statements/download/${accountNum}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (!res.ok) {
        setStatementError(data.error || 'Failed to download bank statement');
        return;
      }
      setDownloadedStatement({
        ...data.statement,
        rawText: data.textDocument,
      });

      // Automatically trigger clean text file download for user
      if (data.textDocument) {
        const blob = new Blob([data.textDocument], { type: 'text/plain;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `Statement_${accountNum}_${new Date().toISOString().substring(0, 10)}.txt`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
      }
    } catch (err: any) {
      setStatementError(err?.message || 'Error downloading statement');
    } finally {
      setIsDownloadingStatement(false);
    }
  }, [token]);

  // Helper to fetch account balance & transactions
  const fetchDashboardData = useCallback(async (activeToken: string, accountId: string) => {
    try {
      const balanceRes = await fetch(`/api/accounts/${accountId}/balance`, {
        headers: { Authorization: `Bearer ${activeToken}` },
      });
      if (balanceRes.ok) {
        const balData = await balanceRes.json();
        setAccount((prev) => (prev ? { ...prev, balance: balData.balance } : null));
      }

      const txRes = await fetch(`/api/accounts/${accountId}/transactions`, {
        headers: { Authorization: `Bearer ${activeToken}` },
      });
      if (txRes.ok) {
        const txData = await txRes.json();
        setTransactions(txData.transactions || []);
      }
    } catch (err) {
      console.error('Failed to load dashboard data:', err);
    }
  }, []);

  // Fetch API key for user
  const fetchApiKeyForUser = useCallback(async (id: number, activeToken?: string) => {
    const curTok = activeToken || token;
    if (!curTok) return;

    setIsFetchingKey(true);
    setKeyError(null);

    try {
      const res = await fetch(`/api/users/${id}/apikey`, {
        headers: { Authorization: `Bearer ${curTok}` },
      });
      const data = await res.json();

      if (!res.ok || !data.success) {
        setKeyError(data.error || 'Unable to retrieve API key');
        setApiKeyData(null);
      } else {
        setApiKeyData({
          userId: data.userId,
          name: data.name,
          username: data.username,
          apiKey: data.apiKey,
        });
      }
    } catch (err: any) {
      setKeyError(err.message || 'Error fetching API key');
    } finally {
      setIsFetchingKey(false);
    }
  }, [token]);

  // Fetch Audit Logs
  const fetchAuditLogs = useCallback(async () => {
    try {
      const res = await fetch('/api/audit/logs');
      if (res.ok) {
        const data = await res.json();
        setAuditLogs(data.logs || []);
      }
    } catch (err) {
      console.error('Failed to fetch audit logs:', err);
    }
  }, []);

  // Fetch Security Alerts
  const fetchAlerts = useCallback(async () => {
    try {
      const res = await fetch('/api/alerts');
      if (res.ok) {
        const data = await res.json();
        setAlerts(data.alerts || []);
      }
    } catch (err) {
      console.error('Failed to fetch alerts:', err);
    }
  }, []);

  // Periodic polling for audit logs and alerts
  useEffect(() => {
    fetchAuditLogs();
    fetchAlerts();
    const interval = setInterval(() => {
      fetchAuditLogs();
      fetchAlerts();
    }, 2500);
    return () => clearInterval(interval);
  }, [fetchAuditLogs, fetchAlerts]);

  // Clear audit log
  const handleClearAudit = async () => {
    try {
      await fetch('/api/audit/clear', { method: 'POST' });
      fetchAuditLogs();
    } catch (err) {
      console.error('Failed to clear audit:', err);
    }
  };

  // Clear alerts
  const handleClearAlerts = async () => {
    try {
      await fetch('/api/alerts/clear', { method: 'POST' });
      fetchAlerts();
    } catch (err) {
      console.error('Failed to clear alerts:', err);
    }
  };

  // Fetch explanation (Gemini AI or Predefined)
  const handleOpenExplain = async (alert: SecurityAlert) => {
    setSelectedAlertForExplain(alert);
    setIsLoadingExplanation(true);
    try {
      const res = await fetch(`/api/alerts/${alert.id}/explain`);
      if (res.ok) {
        const data = await res.json();
        if (data.explanation) {
          setSelectedAlertForExplain((prev) =>
            prev && prev.id === alert.id ? { ...prev, explanation: data.explanation } : prev
          );
        }
      }
    } catch (err) {
      console.error('Failed to fetch explanation:', err);
    } finally {
      setIsLoadingExplanation(false);
    }
  };

  // Bank Login
  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError(null);
    setIsLoggingIn(true);

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: username.trim(),
          password: password.trim(),
        }),
      });

      const data = await res.json();

      if (!res.ok || !data.success) {
        setLoginError(data.error || 'Login failed. Please check your credentials.');
        fetchAuditLogs();
        fetchAlerts();
      } else {
        setToken(data.token);
        setUser(data.user);
        setAccount(data.account);
        setNewEmail(data.user.email);
        setTransferTo(data.user.username === 'Mary' ? 'ACC-2002' : 'ACC-1001');

        if (data.account?.id) {
          fetchDashboardData(data.token, data.account.id);
        }
        fetchApiKeyForUser(data.user.id, data.token);
        fetchAuditLogs();
        fetchAlerts();
      }
    } catch (err: any) {
      setLoginError(err.message || 'Network error.');
    } finally {
      setIsLoggingIn(false);
    }
  };

  // Bank Logout
  const handleLogout = async () => {
    if (token) {
      try {
        await fetch('/api/auth/logout', {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}` },
        });
      } catch (err) {
        console.error('Logout error:', err);
      }
    }
    setToken(null);
    setUser(null);
    setAccount(null);
    setTransactions([]);
    setUsername('');
    setPassword('');
    setLoginError(null);
    setTransferStatus(null);
    setEmailStatus(null);
    setApiKeyData(null);
    setActiveTab('transfer');
    fetchAuditLogs();
    fetchAlerts();
  };

  // SOC Login (admin / admin)
  const handleSocLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setSocLoginError(null);
    setIsSocLoggingIn(true);

    try {
      const res = await fetch('/api/soc/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: socUsername.trim(),
          password: socPassword.trim(),
        }),
      });

      const data = await res.json();

      if (!res.ok || !data.success) {
        setSocLoginError(data.error || 'Authentication failed.');
      } else {
        setSocToken(data.token);
        fetchAuditLogs();
        fetchAlerts();
      }
    } catch (err: any) {
      setSocLoginError(err.message || 'Network error communicating with SOC server.');
    } finally {
      setIsSocLoggingIn(false);
    }
  };

  // Bank Fund Transfer
  const handleTransfer = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token || !account) return;

    setTransferStatus(null);
    setIsTransferring(true);

    try {
      const res = await fetch('/api/transfers', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          toAccountNumber: transferTo.trim(),
          amount: parseFloat(transferAmount),
          description: transferDesc.trim() || 'Fund Transfer',
        }),
      });

      const data = await res.json();

      if (!res.ok || !data.success) {
        setTransferStatus({
          type: 'error',
          message: data.error || 'Transfer failed.',
        });
      } else {
        setTransferStatus({
          type: 'success',
          message: data.message,
        });
        setTransferAmount('');
        setTransferDesc('');
        fetchDashboardData(token, account.id);
      }
      fetchAuditLogs();
      fetchAlerts();
    } catch (err: any) {
      setTransferStatus({
        type: 'error',
        message: err.message || 'Error executing transfer.',
      });
    } finally {
      setIsTransferring(false);
    }
  };

  // Update Email
  const handleUpdateEmail = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token || !user) return;

    setEmailStatus(null);
    setIsUpdatingEmail(true);

    try {
      const res = await fetch(`/api/users/${user.id}/email`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          email: newEmail.trim(),
        }),
      });

      const data = await res.json();

      if (!res.ok || !data.success) {
        setEmailStatus({
          type: 'error',
          message: data.error || 'Failed to update email address.',
        });
      } else {
        setEmailStatus({
          type: 'success',
          message: data.message || 'Email address updated successfully!',
        });
        setUser((prev) => (prev ? { ...prev, email: data.user.email } : null));
      }
      fetchAuditLogs();
      fetchAlerts();
    } catch (err: any) {
      setEmailStatus({
        type: 'error',
        message: err.message || 'Network error updating email.',
      });
    } finally {
      setIsUpdatingEmail(false);
    }
  };

  // Refresh statement history
  const handleRefreshHistory = async () => {
    if (!token || !account) return;
    setIsRefreshingHistory(true);
    await fetchDashboardData(token, account.id);
    await fetchAuditLogs();
    setIsRefreshingHistory(false);
  };

  // Filtered audit logs (plain search filter, no Mary/John segregation buttons)
  const filteredAuditLogs = useMemo(() => {
    if (!auditSearchQuery.trim()) return auditLogs;
    const q = auditSearchQuery.toLowerCase();
    return auditLogs.filter(
      (log) =>
        log.narrative.toLowerCase().includes(q) ||
        log.action.toLowerCase().includes(q) ||
        log.username.toLowerCase().includes(q) ||
        log.endpoint.toLowerCase().includes(q)
    );
  }, [auditLogs, auditSearchQuery]);

  // ========================================================
  // VIEW A: SOC DEFENSE MONITORING PORTAL (DARK CYBER THEME)
  // ========================================================
  if (viewMode === 'soc') {
    // If not authenticated as SOC Admin (admin/admin), show SOC Login Screen
    if (!socToken) {
      return (
        <div className="min-h-screen bg-[#070B14] text-slate-100 flex flex-col justify-center items-center px-4 font-sans selection:bg-cyan-500/30 selection:text-cyan-300">
          <div className="fixed top-0 left-0 right-0 h-1 bg-gradient-to-r from-cyan-500 via-indigo-500 to-emerald-500" />

          <button
            onClick={() => setViewMode('banking')}
            className="fixed top-6 left-6 flex items-center space-x-1.5 px-3 py-1.5 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 hover:text-white text-xs font-mono transition-all"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Return to Banking Portal</span>
          </button>

          <div className="max-w-md w-full bg-slate-900/90 border border-slate-800 rounded-3xl p-8 shadow-2xl backdrop-blur-md space-y-6">
            <div className="text-center space-y-2">
              <div className="w-14 h-14 bg-gradient-to-tr from-cyan-600 to-indigo-600 rounded-2xl flex items-center justify-center mx-auto shadow-lg shadow-cyan-500/20 mb-3 text-white">
                <Shield className="w-7 h-7" />
              </div>
              <h1 className="text-2xl font-mono font-bold text-white tracking-tight">
                Loopback SOC
              </h1>
              <p className="text-xs text-slate-400">
                Security Operations Center • Operator login required
              </p>
            </div>

            <form className="space-y-4 pt-2" onSubmit={handleSocLogin}>
              {socLoginError && (
                <div className="p-3 bg-rose-950/60 border border-rose-800 text-rose-300 rounded-xl text-xs flex items-center space-x-2">
                  <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
                  <span>{socLoginError}</span>
                </div>
              )}

              <div>
                <label className="block text-xs font-mono font-semibold text-cyan-400 mb-1">
                  Operator Username
                </label>
                <input
                  type="text"
                  required
                  value={socUsername}
                  onChange={(e) => setSocUsername(e.target.value)}
                  placeholder="admin"
                  className="w-full px-3.5 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-white font-mono text-sm focus:outline-none focus:border-cyan-500 transition-all"
                />
              </div>

              <div>
                <label className="block text-xs font-mono font-semibold text-cyan-400 mb-1">
                  Operator Password
                </label>
                <input
                  type="password"
                  required
                  value={socPassword}
                  onChange={(e) => setSocPassword(e.target.value)}
                  placeholder="admin"
                  className="w-full px-3.5 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-white font-mono text-sm focus:outline-none focus:border-cyan-500 transition-all"
                />
              </div>

              <button
                type="submit"
                disabled={isSocLoggingIn}
                className="w-full py-2.5 px-4 rounded-xl bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 active:scale-[0.99] text-white font-semibold text-sm transition-all shadow-lg shadow-cyan-600/25 flex items-center justify-center space-x-2 disabled:opacity-50"
              >
                <span>{isSocLoggingIn ? 'Authenticating...' : 'Sign In'}</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </form>
          </div>
        </div>
      );
    }

    // Authenticated SOC Operations Portal
    return (
      <div className="min-h-screen bg-[#070B14] text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-300">
        <header className="bg-slate-900 border-b border-slate-800 sticky top-0 z-40">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="w-10 h-10 bg-cyan-950/80 border border-cyan-700/50 rounded-xl flex items-center justify-center text-cyan-400 shadow-md shadow-cyan-500/10">
                <Activity className="w-6 h-6" />
              </div>
              <div>
                <span className="font-mono font-bold text-base text-white tracking-wider flex items-center gap-2">
                  LOOPBACK <span className="text-xs px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">DEFENSE CONSOLE</span>
                </span>
                <span className="text-[11px] text-slate-400 font-mono">
                  Operator: admin • Real-time Anomaly Detection
                </span>
              </div>
            </div>

            <div className="flex items-center space-x-3">
              <button
                onClick={() => setViewMode('banking')}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-semibold transition-all"
              >
                <ArrowLeft className="w-3.5 h-3.5" />
                <span>Banking App</span>
              </button>

              <button
                onClick={() => setSocToken(null)}
                className="flex items-center space-x-1 px-3 py-1.5 rounded-xl bg-rose-950/60 hover:bg-rose-900/60 border border-rose-800 text-rose-300 text-xs font-semibold transition-all"
              >
                <LogOut className="w-3.5 h-3.5" />
                <span>Exit SOC</span>
              </button>
            </div>
          </div>

          {/* Standalone Tab Navigation: Tab 1: Audit Trail | Tab 2: Security Alerts */}
          <div className="bg-slate-950/80 border-t border-slate-800">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex space-x-2">
              <button
                onClick={() => setSocActiveTab('audit')}
                className={`py-3 px-5 text-xs font-mono font-bold transition-all border-b-2 flex items-center space-x-2 ${
                  socActiveTab === 'audit'
                    ? 'border-cyan-400 text-cyan-300 bg-cyan-500/10'
                    : 'border-transparent text-slate-400 hover:text-white hover:bg-slate-800/40'
                }`}
              >
                <Terminal className="w-4 h-4 text-cyan-400" />
                <span>Audit Trail ({auditLogs.length})</span>
              </button>

              <button
                onClick={() => setSocActiveTab('alerts')}
                className={`py-3 px-5 text-xs font-mono font-bold transition-all border-b-2 flex items-center space-x-2 relative ${
                  socActiveTab === 'alerts'
                    ? 'border-cyan-400 text-cyan-300 bg-cyan-500/10'
                    : 'border-transparent text-slate-400 hover:text-white hover:bg-slate-800/40'
                }`}
              >
                <ShieldCheck className="w-4 h-4 text-cyan-400" />
                <span>Security Alerts</span>
                {alerts.length > 0 && (
                  <span className="px-1.5 py-0.2 rounded-full bg-rose-600 text-white font-mono text-[10px] font-bold">
                    {alerts.length}
                  </span>
                )}
              </button>
            </div>
          </div>
        </header>

        {/* SOC Main Viewport */}
        <main className="max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 flex-1 space-y-6">
          {/* ========================================================
              TAB 1: OLD-SCHOOL BLACK & WHITE AUDIT TRAIL
              ======================================================== */}
          {socActiveTab === 'audit' && (
            <div className="space-y-4 font-mono">
              {/* Header Bar */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-black border border-slate-800 rounded-xl p-4 shadow-xl">
                <div className="flex items-center space-x-3">
                  <div className="w-3 h-3 rounded-full bg-emerald-500 animate-pulse" />
                  <div>
                    <h2 className="text-sm font-bold text-white tracking-wider flex items-center gap-2 uppercase">
                      Chronological Audit Trail
                    </h2>
                    <p className="text-[11px] text-slate-400">
                      Raw chronological session ledger • Continuous stream
                    </p>
                  </div>
                </div>

                <div className="flex items-center space-x-2 text-xs">
                  <div className="relative">
                    <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-500" />
                    <input
                      type="text"
                      value={auditSearchQuery}
                      onChange={(e) => setAuditSearchQuery(e.target.value)}
                      placeholder="Filter log..."
                      className="pl-8 pr-3 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-white text-xs font-mono focus:outline-none focus:border-cyan-400 w-44 sm:w-56"
                    />
                  </div>

                  <button
                    onClick={() => {
                      setIsRefreshingAudit(true);
                      fetchAuditLogs().finally(() => setIsRefreshingAudit(false));
                    }}
                    className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs flex items-center space-x-1"
                    title="Refresh Log"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${isRefreshingAudit ? 'animate-spin' : ''}`} />
                    <span className="hidden sm:inline">Refresh</span>
                  </button>

                  <button
                    onClick={handleClearAudit}
                    className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-rose-950/80 border border-slate-700 hover:border-rose-800 text-slate-300 hover:text-rose-300 text-xs flex items-center space-x-1"
                    title="Clear Log"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    <span className="hidden sm:inline">Clear</span>
                  </button>
                </div>
              </div>

              {/* Old-School Black and White Monospace Terminal Log */}
              <div className="bg-black border border-slate-800 rounded-xl p-5 shadow-2xl overflow-hidden">
                <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-800 text-[11px] text-slate-500">
                  <div className="flex items-center space-x-2">
                    <span className="w-2.5 h-2.5 rounded-full bg-slate-700 inline-block" />
                    <span className="w-2.5 h-2.5 rounded-full bg-slate-700 inline-block" />
                    <span className="w-2.5 h-2.5 rounded-full bg-slate-700 inline-block" />
                    <span className="ml-2 font-mono text-slate-400">/var/log/loopback/audit.log</span>
                  </div>
                  <span>Total Records: {filteredAuditLogs.length}</span>
                </div>

                <div className="font-mono text-xs leading-relaxed overflow-x-auto max-h-[620px] scrollbar-thin scrollbar-thumb-slate-700 space-y-1.5">
                  {filteredAuditLogs.length === 0 ? (
                    <div className="py-12 text-center text-slate-600">
                      [LOG IS EMPTY — EXECUTE ACTIONS IN BANKING PORTAL]
                    </div>
                  ) : (
                    filteredAuditLogs.map((entry, idx) => {
                      const timeStr = new Date(entry.timestamp).toISOString().replace('T', ' ').substring(0, 19);
                      const isError = entry.statusCode >= 400;

                      return (
                        <div
                          key={entry.id || idx}
                          className="flex items-start space-x-3 py-1 px-2 rounded hover:bg-slate-900/80 transition-colors border-l-2 border-transparent hover:border-cyan-400"
                        >
                          <span className="text-slate-500 select-none text-[11px] shrink-0">
                            [{timeStr}]
                          </span>

                          <span className="text-slate-400 shrink-0 font-semibold w-24 truncate">
                            {entry.username || 'ANON'}:
                          </span>

                          <span className="text-white flex-1 font-mono break-words">
                            {entry.narrative}
                          </span>

                          <span className="text-slate-500 text-[11px] shrink-0 hidden md:inline">
                            {entry.method} {entry.endpoint}
                          </span>

                          <span
                            className={`text-[11px] font-bold px-1.5 py-0.2 rounded shrink-0 ${
                              isError
                                ? 'bg-rose-950 text-rose-300 border border-rose-800'
                                : 'bg-slate-800 text-slate-300 border border-slate-700'
                            }`}
                          >
                            {entry.statusCode}
                          </span>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            </div>
          )}

          {/* ========================================================
              TAB 2: SECURITY ALERTS (ANOMALY DETECTION, EXPLAIN, GRAPH)
              ======================================================== */}
          {socActiveTab === 'alerts' && (
            <div className="space-y-6">
              {/* Controls bar */}
              <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-lg flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                  <h2 className="text-lg font-mono font-bold text-white flex items-center gap-2">
                    <ShieldAlert className="w-5 h-5 text-rose-400" />
                    <span>Real-Time Anomaly & Threat Alerts</span>
                  </h2>
                  <p className="text-xs text-slate-400 mt-1">
                    Detects unauthorized parameter tampering, IDOR identifier probes, business logic exploits, and sliding-window enumeration.
                  </p>
                </div>

                <div className="flex items-center space-x-2 text-xs font-mono">
                  <button
                    onClick={() => {
                      setIsRefreshingAlerts(true);
                      fetchAlerts().finally(() => setIsRefreshingAlerts(false));
                    }}
                    className="px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-cyan-300 font-semibold flex items-center space-x-1.5"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${isRefreshingAlerts ? 'animate-spin' : ''}`} />
                    <span>Refresh</span>
                  </button>

                  <button
                    onClick={handleClearAlerts}
                    className="px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-rose-950/60 border border-slate-700 text-rose-400 font-semibold flex items-center space-x-1.5"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    <span>Clear Alerts</span>
                  </button>
                </div>
              </div>

              {/* Alerts List */}
              {alerts.length === 0 ? (
                <div className="bg-slate-900 border border-slate-800 rounded-2xl p-16 text-center space-y-3 font-mono">
                  <div className="w-12 h-12 rounded-2xl bg-slate-800 text-slate-500 flex items-center justify-center mx-auto">
                    <ShieldCheck className="w-6 h-6 text-emerald-400" />
                  </div>
                  <h3 className="text-sm font-bold text-white">No Threat Alerts Triggered</h3>
                  <p className="text-xs text-slate-400 max-w-md mx-auto">
                    All transactions and requests currently match normal baseline behavior. Intercept traffic in Burp Suite and tamper with parameters (e.g. swap IDs or submit negative transfers) to trigger detections.
                  </p>
                </div>
              ) : (
                <div className="space-y-4">
                  {alerts.map((alert) => {
                    const isCritical = alert.severity === 'CRITICAL';
                    const isHigh = alert.severity === 'HIGH';
                    const isMedium = alert.severity === 'MEDIUM';
                    const isLow = alert.severity === 'LOW';
                    const isInfo = alert.severity === 'INFO';

                    return (
                      <div
                        key={alert.id}
                        className={`rounded-2xl border p-5 shadow-xl transition-all ${
                          isCritical
                            ? 'bg-gradient-to-b from-rose-950/40 to-slate-900 border-rose-500/70'
                            : isHigh
                            ? 'bg-gradient-to-b from-rose-950/25 to-slate-900 border-rose-500/40'
                            : isMedium
                            ? 'bg-gradient-to-b from-amber-950/20 to-slate-900 border-amber-500/40'
                            : isInfo
                            ? 'bg-gradient-to-b from-sky-950/25 to-slate-900 border-sky-500/40'
                            : 'bg-slate-900 border-slate-800'
                        }`}
                      >
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800/80">
                          <div className="flex items-center space-x-2.5">
                            <span
                              className={`px-2.5 py-0.5 rounded-lg text-xs font-mono font-bold uppercase tracking-wider ${
                                isCritical
                                  ? 'bg-rose-600 text-white'
                                  : isHigh
                                  ? 'bg-rose-900/80 border border-rose-500 text-rose-200'
                                  : isMedium
                                  ? 'bg-amber-900/80 border border-amber-500 text-amber-200'
                                  : isInfo
                                  ? 'bg-sky-950/80 border border-sky-500 text-sky-200'
                                  : 'bg-slate-800 text-slate-300 border border-slate-700'
                              }`}
                            >
                              {alert.severity === 'INFO' ? 'INFORMATIONAL' : `${alert.severity} SEVERITY`}
                            </span>

                            <span className="text-xs font-mono text-cyan-400 bg-cyan-950/50 border border-cyan-800/60 px-2 py-0.5 rounded-lg">
                              {alert.alertType}
                            </span>
                          </div>

                          <div className="flex items-center space-x-2 text-xs font-mono text-slate-400">
                            <span>{new Date(alert.timestamp).toLocaleTimeString()}</span>
                            <span>•</span>
                            <span>
                              {alert.attemptsCount} Attempt{alert.attemptsCount > 1 ? 's' : ''}
                            </span>
                          </div>
                        </div>

                        {/* Title and summary */}
                        <div className="py-3 space-y-1.5">
                          <h3 className="text-base font-bold text-white flex items-center gap-2">
                            {alert.title}
                          </h3>
                          <p className="text-xs text-slate-300 leading-relaxed font-sans">
                            {alert.summary}
                          </p>
                        </div>

                        {/* Metadata strip */}
                        <div className="py-2.5 px-3 bg-slate-950/80 rounded-xl border border-slate-800 flex flex-wrap items-center gap-3 text-xs font-mono">
                          <span className="text-slate-400">
                            Actor: <strong className="text-white">{alert.username}</strong>
                          </span>
                          <span>•</span>
                          <span className="text-slate-400">
                            Endpoint: <strong className="text-cyan-400">{alert.method} {alert.endpoint}</strong>
                          </span>
                          <span>•</span>
                          <span className="text-slate-400">
                            Status:{' '}
                            <strong className={alert.statusCode < 400 ? 'text-emerald-400' : 'text-rose-400'}>
                              HTTP {alert.statusCode}
                            </strong>
                          </span>
                          {alert.isCrossFunctional && (
                            <>
                              <span>•</span>
                              <span className="text-amber-400 font-bold">
                                Cross-Functional ({alert.affectedEndpoints.length} endpoints)
                              </span>
                            </>
                          )}
                        </div>

                        {/* Action buttons: Explain & Attack Graph */}
                        <div className="mt-4 pt-3 border-t border-slate-800 flex flex-wrap items-center justify-end gap-2.5 font-mono text-xs">
                          <button
                            onClick={() => handleOpenExplain(alert)}
                            className="px-3.5 py-1.5 rounded-xl bg-cyan-600/20 hover:bg-cyan-600/30 border border-cyan-500/50 text-cyan-300 font-semibold flex items-center space-x-1.5 transition-all shadow-sm"
                          >
                            <Brain className="w-3.5 h-3.5" />
                            <span>Explain</span>
                          </button>

                          <button
                            onClick={() => setSelectedAlertForGraph(alert)}
                            className="px-3.5 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 font-semibold flex items-center space-x-1.5 transition-all"
                          >
                            <Network className="w-3.5 h-3.5 text-cyan-400" />
                            <span>Attack Graph</span>
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}
        </main>

        {/* ========================================================
            MODAL 1: EXPLAIN ALERT MODAL (GEMINI AI / OFFLINE RULE)
            ======================================================== */}
        {selectedAlertForExplain && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-150">
            <div className="max-w-2xl w-full bg-slate-900 border border-slate-700 rounded-3xl p-6 sm:p-8 shadow-2xl space-y-5 max-h-[90vh] overflow-y-auto">
              {/* Header */}
              <div className="flex items-start justify-between gap-3 pb-3 border-b border-slate-800">
                <div>
                  <div className="flex items-center space-x-2 mb-1">
                    <span className="px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 text-[11px] font-mono font-bold flex items-center gap-1">
                      <Brain className="w-3 h-3" />
                      {selectedAlertForExplain.explanation.source === 'AI_GEMINI'
                        ? 'Gemini 2.5 Flash'
                        : 'Offline Predefined Rule'}
                    </span>
                    <span className="text-[11px] font-mono text-slate-400">
                      {selectedAlertForExplain.alertType}
                    </span>
                  </div>
                  <h3 className="text-lg font-bold text-white">
                    {selectedAlertForExplain.title}
                  </h3>
                </div>

                <button
                  onClick={() => setSelectedAlertForExplain(null)}
                  className="p-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              {isLoadingExplanation ? (
                <div className="py-12 text-center space-y-3 font-mono">
                  <RefreshCw className="w-6 h-6 animate-spin text-cyan-400 mx-auto" />
                  <p className="text-xs text-slate-400">Analyzing threat pattern with Gemini...</p>
                </div>
              ) : (
                <div className="space-y-4 text-xs font-sans">
                  {/* Overview */}
                  <div className="p-3.5 rounded-2xl bg-slate-950 border border-slate-800 space-y-1">
                    <span className="font-mono font-bold text-cyan-400 block uppercase text-[10px]">
                      Threat Overview
                    </span>
                    <p className="text-slate-300 leading-relaxed">
                      {selectedAlertForExplain.explanation.overview}
                    </p>
                  </div>

                  {/* Root Cause */}
                  <div className="p-3.5 rounded-2xl bg-slate-950 border border-slate-800 space-y-1">
                    <span className="font-mono font-bold text-rose-400 block uppercase text-[10px]">
                      Root Cause
                    </span>
                    <p className="text-slate-300 leading-relaxed font-mono text-[11px]">
                      {selectedAlertForExplain.explanation.rootCause}
                    </p>
                  </div>

                  {/* Attack Mechanics */}
                  <div className="p-3.5 rounded-2xl bg-slate-950 border border-slate-800 space-y-1">
                    <span className="font-mono font-bold text-amber-400 block uppercase text-[10px]">
                      Attack Mechanics & Exploitation
                    </span>
                    <p className="text-slate-300 leading-relaxed font-mono text-[11px]">
                      {selectedAlertForExplain.explanation.attackMechanics}
                    </p>
                  </div>

                  {/* Business Impact */}
                  <div className="p-3.5 rounded-2xl bg-slate-950 border border-slate-800 space-y-1">
                    <span className="font-mono font-bold text-indigo-400 block uppercase text-[10px]">
                      Business & Compliance Impact
                    </span>
                    <p className="text-slate-300 leading-relaxed">
                      {selectedAlertForExplain.explanation.businessImpact}
                    </p>
                  </div>

                  {/* Remediation */}
                  <div className="p-3.5 rounded-2xl bg-emerald-950/30 border border-emerald-800/60 space-y-1">
                    <span className="font-mono font-bold text-emerald-400 block uppercase text-[10px]">
                      Remediation & Defense Strategy
                    </span>
                    <p className="text-emerald-200 leading-relaxed font-mono text-[11px]">
                      {selectedAlertForExplain.explanation.remediation}
                    </p>
                  </div>
                </div>
              )}

              <div className="pt-2 flex justify-end">
                <button
                  onClick={() => setSelectedAlertForExplain(null)}
                  className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-white font-mono text-xs font-semibold"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================
            MODAL 2: VISUAL ATTACK GRAPH MODAL
            ======================================================== */}
        {selectedAlertForGraph && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-150">
            <div className="max-w-4xl w-full bg-slate-900 border border-slate-700 rounded-3xl p-6 sm:p-8 shadow-2xl space-y-6 max-h-[92vh] overflow-y-auto">
              {/* Header */}
              <div className="flex items-start justify-between gap-3 pb-3 border-b border-slate-800">
                <div>
                  <div className="flex items-center space-x-2 mb-1">
                    <span className="px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 text-[11px] font-mono font-bold flex items-center gap-1">
                      <Network className="w-3 h-3" />
                      Visual Attack Graph
                    </span>
                    <span className="text-[11px] font-mono text-slate-400">
                      Step-by-Step Incident Progression
                    </span>
                  </div>
                  <h3 className="text-lg font-bold text-white">
                    {selectedAlertForGraph.title}
                  </h3>
                </div>

                <button
                  onClick={() => setSelectedAlertForGraph(null)}
                  className="p-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              {/* Graphical Node Map Visualizer */}
              <div className="bg-slate-950 border border-slate-800 rounded-2xl p-6 relative overflow-hidden">
                <div className="text-[10px] font-mono uppercase text-slate-500 tracking-wider mb-4">
                  Threat Interaction Topology
                </div>

                {/* Node Grid Visualization */}
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 relative">
                  {selectedAlertForGraph.attackGraph.nodes.map((node, i) => (
                    <div
                      key={node.id}
                      className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex flex-col justify-between space-y-2 relative group hover:border-cyan-500/60 transition-all"
                    >
                      <div className="flex items-center justify-between">
                        <span
                          className={`text-[9px] font-mono font-bold uppercase px-2 py-0.5 rounded ${
                            node.type === 'actor'
                              ? 'bg-rose-950 text-rose-300 border border-rose-800'
                              : node.type === 'endpoint'
                              ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                              : node.type === 'target'
                              ? 'bg-amber-950 text-amber-300 border border-amber-800'
                              : 'bg-indigo-950 text-indigo-300 border border-indigo-800'
                          }`}
                        >
                          {node.type}
                        </span>
                        <span className="text-[10px] font-mono text-slate-500">#{i + 1}</span>
                      </div>

                      <div>
                        <div className="text-xs font-bold text-white font-mono break-words">
                          {node.label}
                        </div>
                        <div className="text-[11px] text-slate-400 mt-1 font-sans">
                          {node.details}
                        </div>
                      </div>

                      {i < selectedAlertForGraph.attackGraph.nodes.length - 1 && (
                        <div className="hidden md:block absolute -right-3 top-1/2 -translate-y-1/2 z-10 text-cyan-400">
                          <ChevronRight className="w-4 h-4" />
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* Step-by-Step Chronological Progression Flow */}
              <div className="space-y-3 font-mono">
                <div className="text-[10px] uppercase text-slate-500 tracking-wider">
                  Attack Sequence Flow ({selectedAlertForGraph.attackGraph.steps.length} Steps)
                </div>

                <div className="space-y-3">
                  {selectedAlertForGraph.attackGraph.steps.map((step) => (
                    <div
                      key={step.stepNumber}
                      className="p-4 rounded-2xl bg-slate-950 border border-slate-800/90 flex flex-col sm:flex-row sm:items-start justify-between gap-3 text-xs"
                    >
                      <div className="flex items-start space-x-3">
                        <div className="w-6 h-6 rounded-full bg-slate-800 text-cyan-300 font-bold flex items-center justify-center shrink-0 text-xs">
                          {step.stepNumber}
                        </div>
                        <div className="space-y-1">
                          <div className="flex items-center space-x-2">
                            <span className="font-bold text-white">{step.title}</span>
                            <span className="text-[10px] px-2 py-0.2 rounded bg-slate-900 border border-slate-700 text-slate-400">
                              {step.phase}
                            </span>
                          </div>
                          <p className="text-slate-300 font-sans text-xs leading-relaxed">
                            {step.description}
                          </p>
                          <div className="flex flex-wrap items-center gap-2 pt-1 text-[11px] text-slate-500">
                            <span>Actor: <strong className="text-slate-300">{step.actor}</strong></span>
                            <span>→</span>
                            <span>Target: <strong className="text-cyan-400">{step.target}</strong></span>
                          </div>
                        </div>
                      </div>

                      <div className="shrink-0">
                        <span
                          className={`px-2 py-1 rounded text-[10px] font-bold ${
                            step.status === 'SUCCESS'
                              ? 'bg-rose-950 text-rose-300 border border-rose-800'
                              : step.status === 'FLAGGED'
                              ? 'bg-amber-950 text-amber-300 border border-amber-800'
                              : 'bg-slate-800 text-slate-300'
                          }`}
                        >
                          {step.status}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="pt-2 flex justify-end">
                <button
                  onClick={() => setSelectedAlertForGraph(null)}
                  className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-white font-mono text-xs font-semibold"
                >
                  Close Graph
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    );
  }

  // ========================================================
  // VIEW B: BANKING LOGIN SCREEN (CLEAN CREAM & MAROON)
  // ========================================================
  if (!token || !user || !account) {
    return (
      <div className="min-h-screen bg-[#FDFBF7] text-[#2B2122] flex flex-col justify-center items-center px-4 font-sans selection:bg-[#701318]/20 selection:text-[#701318]">
        <div className="fixed top-0 left-0 right-0 h-1.5 bg-gradient-to-r from-[#5B0E11] via-[#701318] to-[#912028]" />

        {/* Discrete corner button to view SOC */}
        <div className="fixed top-4 right-4 z-50">
          <button
            onClick={() => setViewMode('soc')}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-xl bg-[#FFFFFF] border border-[#EADBCE] hover:border-[#701318] text-[#701318] text-xs font-semibold transition-all shadow-sm"
          >
            <Shield className="w-3.5 h-3.5 text-[#701318]" />
            <span>SOC Console</span>
          </button>
        </div>

        <div className="max-w-md w-full bg-[#FFFFFF] border border-[#EADBCE] rounded-3xl p-8 shadow-xl shadow-[#701318]/5 space-y-6">
          <div className="text-center space-y-2">
            <div className="w-14 h-14 bg-gradient-to-br from-[#701318] to-[#500C10] rounded-2xl flex items-center justify-center mx-auto shadow-md shadow-[#701318]/20 mb-3 text-white">
              <Landmark className="w-7 h-7" />
            </div>
            <h1 className="text-2xl font-serif font-bold text-[#5B0E11] tracking-tight">
              Apex Trust Private Bank
            </h1>
            <p className="text-xs text-[#7A6667]">
              Secure Client Portal • Sign in to your account
            </p>
          </div>

          <form className="space-y-4 pt-2" onSubmit={handleLogin}>
            {loginError && (
              <div className="p-3 bg-[#FDF2F2] border border-[#F5C2C7] text-[#842029] rounded-xl text-xs flex items-center space-x-2">
                <AlertCircle className="w-4 h-4 shrink-0 text-[#842029]" />
                <span>{loginError}</span>
              </div>
            )}

            <div>
              <label className="block text-xs font-semibold text-[#5B0E11] mb-1">
                Username
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-[#9B8788]">
                  <User className="h-4 w-4" />
                </div>
                <input
                  type="text"
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="Username"
                  className="w-full pl-10 pr-3.5 py-2.5 bg-[#FAF7F2] border border-[#DFD4C5] rounded-xl text-[#2B2122] text-sm focus:outline-none focus:border-[#701318] focus:ring-1 focus:ring-[#701318] transition-all font-medium"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold text-[#5B0E11] mb-1">
                Password
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-[#9B8788]">
                  <Lock className="h-4 w-4" />
                </div>
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Password"
                  className="w-full pl-10 pr-3.5 py-2.5 bg-[#FAF7F2] border border-[#DFD4C5] rounded-xl text-[#2B2122] text-sm focus:outline-none focus:border-[#701318] focus:ring-1 focus:ring-[#701318] transition-all font-medium"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={isLoggingIn}
              className="w-full py-2.5 px-4 rounded-xl bg-[#701318] hover:bg-[#5B0E11] active:scale-[0.99] text-white font-semibold text-sm transition-all shadow-md shadow-[#701318]/25 flex items-center justify-center space-x-2 disabled:opacity-50"
            >
              <span>{isLoggingIn ? 'Signing in...' : 'Sign In'}</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </form>
        </div>
      </div>
    );
  }

  // ========================================================
  // VIEW C: LOGGED-IN BANKING APP (CLEAN CREAM & MAROON)
  // ========================================================
  return (
    <div className="min-h-screen bg-[#FDFBF7] text-[#2B2122] flex flex-col font-sans selection:bg-[#701318]/20 selection:text-[#701318]">
      {/* Top Maroon Navigation Header */}
      <header className="bg-[#701318] text-[#FDFBF7] shadow-lg sticky top-0 z-40">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 bg-[#FAF7F2] rounded-xl flex items-center justify-center text-[#701318] shadow-sm">
              <Landmark className="w-6 h-6" />
            </div>
            <div>
              <span className="font-serif font-bold text-lg text-white tracking-tight">
                Apex Trust Bank
              </span>
              <span className="hidden sm:inline-block ml-2 text-[10px] font-mono bg-[#580F13] px-2 py-0.5 rounded text-[#F7E8E9]">
                Private Banking
              </span>
            </div>
          </div>

          <div className="flex items-center space-x-3">
            <div className="text-right hidden sm:block">
              <div className="text-xs text-[#F7E8E9] font-medium">Account Holder</div>
              <div className="text-sm font-bold text-white">{user.name}</div>
            </div>

            {/* Discrete SOC Console Button */}
            <button
              onClick={() => setViewMode('soc')}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-xl bg-[#FAF7F2] hover:bg-[#F3EDE2] text-[#701318] text-xs font-semibold transition-all shadow-sm"
            >
              <Shield className="w-3.5 h-3.5 text-[#701318]" />
              <span>SOC Console</span>
            </button>

            {/* Sign Out Button */}
            <button
              onClick={handleLogout}
              className="flex items-center space-x-1 px-3 py-1.5 rounded-xl bg-[#580F13] hover:bg-[#480B0F] text-[#FDFBF7] text-xs font-semibold transition-all shadow-sm"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span>Sign Out</span>
            </button>
          </div>
        </div>

        {/* Navigation Tabs Bar */}
        <div className="bg-[#580F13] border-t border-[#7B181E]/60">
          <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 flex space-x-2 overflow-x-auto scrollbar-none">
            <button
              onClick={() => setActiveTab('transfer')}
              className={`py-3 px-4 text-xs font-bold transition-all border-b-2 flex items-center space-x-2 whitespace-nowrap ${
                activeTab === 'transfer'
                  ? 'border-[#FDFBF7] text-white bg-[#701318]/50'
                  : 'border-transparent text-[#EAD0D2] hover:text-white hover:bg-[#701318]/25'
              }`}
            >
              <Send className="w-3.5 h-3.5" />
              <span>Send Money</span>
            </button>

            <button
              onClick={() => {
                setActiveTab('history');
                handleRefreshHistory();
              }}
              className={`py-3 px-4 text-xs font-bold transition-all border-b-2 flex items-center space-x-2 whitespace-nowrap ${
                activeTab === 'history'
                  ? 'border-[#FDFBF7] text-white bg-[#701318]/50'
                  : 'border-transparent text-[#EAD0D2] hover:text-white hover:bg-[#701318]/25'
              }`}
            >
              <History className="w-3.5 h-3.5" />
              <span>Transfer History</span>
            </button>

            <button
              onClick={() => setActiveTab('email')}
              className={`py-3 px-4 text-xs font-bold transition-all border-b-2 flex items-center space-x-2 whitespace-nowrap ${
                activeTab === 'email'
                  ? 'border-[#FDFBF7] text-white bg-[#701318]/50'
                  : 'border-transparent text-[#EAD0D2] hover:text-white hover:bg-[#701318]/25'
              }`}
            >
              <Mail className="w-3.5 h-3.5" />
              <span>Profile Settings</span>
            </button>

            <button
              onClick={() => {
                setActiveTab('apikey');
                if (user) {
                  fetchApiKeyForUser(user.id);
                }
              }}
              className={`py-3 px-4 text-xs font-bold transition-all border-b-2 flex items-center space-x-2 whitespace-nowrap ${
                activeTab === 'apikey'
                  ? 'border-[#FDFBF7] text-white bg-[#701318]/50'
                  : 'border-transparent text-[#EAD0D2] hover:text-white hover:bg-[#701318]/25'
              }`}
            >
              <Key className="w-3.5 h-3.5" />
              <span>Developer API Keys</span>
            </button>
          </div>
        </div>
      </header>

      {/* Main Tab Viewport */}
      <main className="max-w-6xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 flex-1 space-y-6">
        {/* Account Balance Overview Card */}
        <div className="bg-[#FFFFFF] border border-[#EADBCE] rounded-3xl p-6 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center space-x-4">
            <div className="w-12 h-12 rounded-2xl bg-[#F7E8E9] text-[#701318] flex items-center justify-center font-bold">
              <CreditCard className="w-6 h-6" />
            </div>
            <div>
              <span className="text-[11px] font-bold uppercase tracking-wider text-[#7A6667]">
                Primary Checking
              </span>
              <div className="flex items-baseline space-x-2">
                <span className="text-3xl font-extrabold text-[#701318] tracking-tight">
                  ${account.balance.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}
                </span>
                <span className="text-xs font-semibold text-[#7A6667]">{account.currency}</span>
              </div>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3 text-xs font-mono text-[#7A6667]">
            <div className="bg-[#FAF7F2] border border-[#DFD4C5] px-3.5 py-1.5 rounded-xl">
              Account: <strong className="text-[#701318]">{account.accountNumber}</strong>
            </div>
          </div>
        </div>

        {/* ========================================================
            TAB 1: SEND MONEY (MAIN TAB)
            ======================================================== */}
        {activeTab === 'transfer' && (
          <div className="max-w-2xl mx-auto bg-[#FFFFFF] border border-[#EADBCE] rounded-3xl p-6 sm:p-8 shadow-sm space-y-6">
            <div>
              <h2 className="text-lg font-serif font-bold text-[#5B0E11]">
                Transfer Funds
              </h2>
              <p className="text-xs text-[#7A6667] mt-0.5">
                Send money directly to another client account.
              </p>
            </div>

            <form onSubmit={handleTransfer} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-[#5B0E11] mb-1">
                  Recipient Account Number
                </label>
                <input
                  type="text"
                  required
                  value={transferTo}
                  onChange={(e) => setTransferTo(e.target.value)}
                  placeholder="e.g. ACC-2002"
                  className="w-full px-3.5 py-2.5 bg-[#FAF7F2] border border-[#DFD4C5] rounded-xl text-[#2B2122] text-sm font-mono focus:outline-none focus:border-[#701318] focus:ring-1 focus:ring-[#701318]"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-[#5B0E11] mb-1">
                  Amount (USD)
                </label>
                <div className="relative">
                  <span className="absolute left-3.5 top-2.5 text-[#9B8788] text-sm font-bold">$</span>
                  <input
                    type="number"
                    step="0.01"
                    required
                    value={transferAmount}
                    onChange={(e) => setTransferAmount(e.target.value)}
                    placeholder="0.00"
                    className="w-full pl-8 pr-3.5 py-2.5 bg-[#FAF7F2] border border-[#DFD4C5] rounded-xl text-[#2B2122] text-sm font-mono focus:outline-none focus:border-[#701318] focus:ring-1 focus:ring-[#701318]"
                  />
                </div>

                <div className="flex items-center space-x-2 mt-2 text-[11px] text-[#7A6667]">
                  <span>Quick Amounts:</span>
                  {['25.00', '50.00', '100.00', '250.00'].map((amt) => (
                    <button
                      key={amt}
                      type="button"
                      onClick={() => setTransferAmount(amt)}
                      className="px-2 py-0.5 rounded bg-[#FAF7F2] hover:bg-[#F3EDE2] border border-[#DFD4C5] text-[#701318] font-mono text-[10px]"
                    >
                      ${amt}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-[#5B0E11] mb-1">
                  Memo
                </label>
                <input
                  type="text"
                  value={transferDesc}
                  onChange={(e) => setTransferDesc(e.target.value)}
                  placeholder="e.g. Settlement / Reimbursement"
                  className="w-full px-3.5 py-2.5 bg-[#FAF7F2] border border-[#DFD4C5] rounded-xl text-[#2B2122] text-sm focus:outline-none focus:border-[#701318] focus:ring-1 focus:ring-[#701318]"
                />
              </div>

              {transferStatus && (
                <div
                  className={`p-3.5 rounded-xl text-xs flex items-center space-x-2 ${
                    transferStatus.type === 'success'
                      ? 'bg-[#EBF9F1] border border-[#B9E9CB] text-[#1E6B38]'
                      : 'bg-[#FDF2F2] border border-[#F5C2C7] text-[#842029]'
                  }`}
                >
                  {transferStatus.type === 'success' ? (
                    <CheckCircle2 className="w-4 h-4 shrink-0 text-[#1E6B38]" />
                  ) : (
                    <AlertCircle className="w-4 h-4 shrink-0 text-[#842029]" />
                  )}
                  <span>{transferStatus.message}</span>
                </div>
              )}

              <button
                type="submit"
                disabled={isTransferring}
                className="w-full py-3 px-4 rounded-xl bg-[#701318] hover:bg-[#5B0E11] active:scale-[0.99] text-white font-semibold text-sm transition-all shadow-md shadow-[#701318]/25 flex items-center justify-center space-x-2 disabled:opacity-50"
              >
                <Send className="w-4 h-4" />
                <span>{isTransferring ? 'Processing...' : 'Send Transfer'}</span>
              </button>
            </form>
          </div>
        )}

        {/* ========================================================
            TAB 2: TRANSFER HISTORY TAB
            ======================================================== */}
        {activeTab === 'history' && (
          <div className="bg-[#FFFFFF] border border-[#EADBCE] rounded-3xl p-6 sm:p-8 shadow-sm space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-[#EADBCE]">
              <div>
                <h2 className="text-lg font-serif font-bold text-[#5B0E11]">
                  Account Statements
                </h2>
                <p className="text-xs text-[#7A6667] mt-0.5">
                  Recent account transactions, official bank ledger, and statements.
                </p>
              </div>

              <div className="flex items-center space-x-2">
                <button
                  onClick={() => handleDownloadStatement(account?.accountNumber || 'ACC-1001')}
                  disabled={isDownloadingStatement}
                  className="px-3.5 py-2 rounded-xl bg-[#701318] hover:bg-[#5B0E11] text-white text-xs font-semibold flex items-center space-x-1.5 transition-all shadow-sm shadow-[#701318]/25 disabled:opacity-50"
                >
                  <Download className={`w-3.5 h-3.5 ${isDownloadingStatement ? 'animate-bounce' : ''}`} />
                  <span>{isDownloadingStatement ? 'Downloading...' : 'Download Statement'}</span>
                </button>

                <button
                  onClick={handleRefreshHistory}
                  disabled={isRefreshingHistory}
                  className="px-3.5 py-2 rounded-xl bg-[#FAF7F2] hover:bg-[#F3EDE2] border border-[#DFD4C5] text-[#701318] text-xs font-semibold flex items-center space-x-1.5 transition-all shadow-sm"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${isRefreshingHistory ? 'animate-spin' : ''}`} />
                  <span>{isRefreshingHistory ? 'Refreshing...' : 'Refresh'}</span>
                </button>
              </div>
            </div>

            {/* Account & Registered Address Banner */}
            <div className="p-4 rounded-2xl bg-[#FAF7F2] border border-[#EADBCE] flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="space-y-1">
                <div className="text-[10px] font-mono uppercase tracking-wider text-[#7A6667]">
                  Account Holder Registered Details
                </div>
                <div className="text-sm font-bold text-[#5B0E11] flex items-center gap-2">
                  <Building2 className="w-4 h-4 text-[#701318]" />
                  <span>{user.name}</span>
                  <span className="text-xs font-mono font-medium text-[#7A6667]">
                    • Account {account?.accountNumber || 'ACC-1001'}
                  </span>
                </div>
                <div className="text-xs text-[#5B0E11]/85">
                  <span className="font-semibold text-[#701318]">Fixed Address:</span> {user.address || '14 Samora Machel Avenue, Harare, Zimbabwe'}
                </div>
              </div>

              <div className="flex items-center space-x-3 shrink-0">
                <button
                  onClick={() => handleDownloadStatement(account?.accountNumber || 'ACC-1001')}
                  disabled={isDownloadingStatement}
                  className="px-3 py-1.5 rounded-xl bg-[#FFFFFF] hover:bg-[#F3EDE2] border border-[#DFD4C5] text-[#701318] text-xs font-semibold flex items-center space-x-1.5 transition-all shadow-sm"
                >
                  <FileText className="w-3.5 h-3.5" />
                  <span>Official Text Export</span>
                </button>
              </div>
            </div>

            {statementError && (
              <div className="p-3 bg-[#FDF2F2] border border-[#F5C2C7] text-[#842029] rounded-xl text-xs flex items-center space-x-2">
                <AlertCircle className="w-4 h-4 shrink-0 text-[#842029]" />
                <span>{statementError}</span>
              </div>
            )}

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-[#FAF7F2] text-[#7A6667] uppercase font-mono border-b border-[#EADBCE]">
                  <tr>
                    <th className="px-4 py-3 rounded-l-xl">Date & Time</th>
                    <th className="px-4 py-3">Type</th>
                    <th className="px-4 py-3">Description</th>
                    <th className="px-4 py-3">Account</th>
                    <th className="px-4 py-3 text-right rounded-r-xl">Amount</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#EADBCE] text-[#2B2122]">
                  {transactions.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="py-8 text-center text-[#9B8788]">
                        No transactions recorded for this account.
                      </td>
                    </tr>
                  ) : (
                    transactions.map((tx) => (
                      <tr key={tx.id} className="hover:bg-[#FAF7F2]/60 transition-colors">
                        <td className="px-4 py-3 font-mono text-[#7A6667]">
                          {new Date(tx.timestamp).toLocaleString()}
                        </td>
                        <td className="px-4 py-3">
                          <span
                            className={`px-2 py-0.5 rounded-md font-bold text-[10px] inline-flex items-center gap-1 ${
                              tx.type === 'DEPOSIT'
                                ? 'bg-[#EBF9F1] text-[#1E6B38]'
                                : 'bg-[#FDF2F2] text-[#842029]'
                            }`}
                          >
                            {tx.type === 'DEPOSIT' ? (
                              <ArrowDownLeft className="w-3 h-3" />
                            ) : (
                              <ArrowUpRight className="w-3 h-3" />
                            )}
                            {tx.type}
                          </span>
                        </td>
                        <td className="px-4 py-3 font-medium text-[#2B2122]">
                          {tx.description}
                        </td>
                        <td className="px-4 py-3 font-mono text-[#701318]">
                          {tx.toAccountNumber}
                        </td>
                        <td
                          className={`px-4 py-3 text-right font-mono font-bold text-sm ${
                            tx.type === 'DEPOSIT' ? 'text-[#1E6B38]' : 'text-[#842029]'
                          }`}
                        >
                          {tx.type === 'DEPOSIT' ? '+' : '-'}${tx.amount.toFixed(2)}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ========================================================
            TAB 3: UPDATE EMAIL (PROFILE SETTINGS)
            ======================================================== */}
        {activeTab === 'email' && (
          <div className="max-w-2xl mx-auto bg-[#FFFFFF] border border-[#EADBCE] rounded-3xl p-6 sm:p-8 shadow-sm space-y-6">
            <div>
              <h2 className="text-lg font-serif font-bold text-[#5B0E11]">
                Profile Settings
              </h2>
              <p className="text-xs text-[#7A6667] mt-0.5">
                Manage your registered contact information.
              </p>
            </div>

            <div className="p-4 bg-[#FAF7F2] border border-[#DFD4C5] rounded-2xl grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
              <div>
                <span className="text-[#9B8788] block text-[10px] uppercase font-bold">Client Name</span>
                <span className="font-semibold text-[#2B2122]">{user.name}</span>
              </div>
              <div>
                <span className="text-[#9B8788] block text-[10px] uppercase font-bold">Current Registered Email</span>
                <span className="font-mono text-[#2B2122]">{user.email}</span>
              </div>
            </div>

            <form onSubmit={handleUpdateEmail} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-[#5B0E11] mb-1">
                  New Email Address
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-[#9B8788]">
                    <Mail className="h-4 w-4" />
                  </div>
                  <input
                    type="email"
                    required
                    value={newEmail}
                    onChange={(e) => setNewEmail(e.target.value)}
                    placeholder="name@apexbank.test"
                    className="w-full pl-10 pr-3.5 py-2.5 bg-[#FAF7F2] border border-[#DFD4C5] rounded-xl text-[#2B2122] text-sm font-mono focus:outline-none focus:border-[#701318] focus:ring-1 focus:ring-[#701318]"
                  />
                </div>
              </div>

              {emailStatus && (
                <div
                  className={`p-3.5 rounded-xl text-xs flex items-center space-x-2 ${
                    emailStatus.type === 'success'
                      ? 'bg-[#EBF9F1] border border-[#B9E9CB] text-[#1E6B38]'
                      : 'bg-[#FDF2F2] border border-[#F5C2C7] text-[#842029]'
                  }`}
                >
                  {emailStatus.type === 'success' ? (
                    <CheckCircle2 className="w-4 h-4 shrink-0 text-[#1E6B38]" />
                  ) : (
                    <AlertCircle className="w-4 h-4 shrink-0 text-[#842029]" />
                  )}
                  <span>{emailStatus.message}</span>
                </div>
              )}

              <button
                type="submit"
                disabled={isUpdatingEmail}
                className="w-full py-3 px-4 rounded-xl bg-[#701318] hover:bg-[#5B0E11] active:scale-[0.99] text-white font-semibold text-sm transition-all shadow-md shadow-[#701318]/25 flex items-center justify-center space-x-2 disabled:opacity-50"
              >
                <Mail className="w-4 h-4" />
                <span>{isUpdatingEmail ? 'Updating...' : 'Save Email Address'}</span>
              </button>
            </form>
          </div>
        )}

        {/* ========================================================
            TAB 4: DEVELOPER API KEYS (CLEAN LOOK, PROXIABLE API)
            ======================================================== */}
        {activeTab === 'apikey' && (
          <div className="max-w-2xl mx-auto bg-[#FFFFFF] border border-[#EADBCE] rounded-3xl p-6 sm:p-8 shadow-sm space-y-6">
            <div>
              <h2 className="text-lg font-serif font-bold text-[#5B0E11]">
                Developer API Credentials
              </h2>
              <p className="text-xs text-[#7A6667] mt-0.5">
                Active secret key for API integrations and programmatic balance checking.
              </p>
            </div>

            {keyError && (
              <div className="p-3.5 bg-[#FDF2F2] border border-[#F5C2C7] text-[#842029] rounded-xl text-xs flex items-center space-x-2">
                <AlertCircle className="w-4 h-4 shrink-0 text-[#842029]" />
                <span>{keyError}</span>
              </div>
            )}

            {apiKeyData ? (
              <div className="p-5 rounded-2xl bg-[#FAF7F2] border border-[#DFD4C5] space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-[#5B0E11]">
                    Production Secret Key
                  </span>
                  <span className="text-[11px] font-mono text-[#7A6667]">
                    Account: {apiKeyData.name}
                  </span>
                </div>

                <div className="flex items-center space-x-2">
                  <div className="flex-1 p-3 bg-[#FFFFFF] border border-[#DFD4C5] rounded-xl font-mono text-xs text-[#2B2122] flex items-center justify-between">
                    <span>
                      {showRawKey
                        ? apiKeyData.apiKey
                        : `${apiKeyData.apiKey.substring(0, 16)}••••••••••••••••••••••••`}
                    </span>

                    <button
                      type="button"
                      onClick={() => setShowRawKey(!showRawKey)}
                      className="text-[#7A6667] hover:text-[#2B2122] ml-2"
                      title={showRawKey ? 'Hide key' : 'Show key'}
                    >
                      {showRawKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>

                  <button
                    type="button"
                    onClick={() => {
                      navigator.clipboard.writeText(apiKeyData.apiKey);
                      setCopiedKey(true);
                      setTimeout(() => setCopiedKey(false), 2000);
                    }}
                    className="px-3 py-3 bg-[#FFFFFF] border border-[#DFD4C5] hover:bg-[#F3EDE2] rounded-xl text-[#701318] text-xs font-semibold"
                    title="Copy Key"
                  >
                    {copiedKey ? <CheckCircle2 className="w-4 h-4 text-emerald-600" /> : <Copy className="w-4 h-4" />}
                  </button>
                </div>

                <p className="text-[11px] text-[#7A6667] leading-relaxed">
                  Keep this secret key secure. It provides programmatic access to execute transactions and query account balances.
                </p>
              </div>
            ) : (
              <div className="p-6 text-center text-[#9B8788] text-xs">
                {isFetchingKey ? 'Loading credentials...' : 'No key generated.'}
              </div>
            )}
          </div>
        )}
      </main>

      {/* Realistic Bank Footer */}
      <footer className="border-t border-[#EADBCE] bg-[#FAF7F2] py-4 text-xs text-[#7A6667] text-center">
        <p>© 2026 Apex Trust Bank, N.A. Member FDIC. All rights reserved.</p>
      </footer>

      {/* Official Downloaded Statement Modal */}
      {downloadedStatement && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-in fade-in duration-150">
          <div className="max-w-2xl w-full bg-white border border-[#DFD4C5] rounded-3xl p-6 sm:p-8 shadow-2xl space-y-6 max-h-[92vh] overflow-y-auto font-sans">
            {/* Bank Header */}
            <div className="flex items-start justify-between border-b border-[#EADBCE] pb-4">
              <div className="space-y-1">
                <div className="flex items-center space-x-2">
                  <Landmark className="w-6 h-6 text-[#701318]" />
                  <span className="font-serif font-bold text-lg text-[#5B0E11]">
                    {downloadedStatement.bankName}
                  </span>
                </div>
                <p className="text-[11px] text-[#7A6667]">
                  {downloadedStatement.bankAddress}
                </p>
                <div className="text-[10px] font-mono text-[#701318] pt-1">
                  Official Statement Ref: <span className="font-bold">{downloadedStatement.statementId}</span>
                </div>
              </div>

              <button
                onClick={() => setDownloadedStatement(null)}
                className="p-1.5 rounded-xl bg-[#FAF7F2] hover:bg-[#F3EDE2] text-[#7A6667] hover:text-[#2B2122]"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Account Details Box */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 p-4 rounded-2xl bg-[#FAF7F2] border border-[#EADBCE] text-xs">
              <div>
                <span className="text-[10px] uppercase font-mono text-[#7A6667] block">Account Holder</span>
                <span className="font-bold text-[#5B0E11] text-sm block">{downloadedStatement.accountHolder.name}</span>
                <span className="text-slate-600 block text-[11px] mt-0.5">{downloadedStatement.accountHolder.email}</span>
                <span className="text-[#701318] font-medium block text-[11px] mt-1">
                  📍 {downloadedStatement.accountHolder.address}
                </span>
              </div>
              <div className="sm:text-right">
                <span className="text-[10px] uppercase font-mono text-[#7A6667] block">Account Summary</span>
                <span className="font-mono font-bold text-[#701318] text-sm block">
                  {downloadedStatement.account.accountNumber} ({downloadedStatement.account.type})
                </span>
                <span className="text-slate-600 block text-[11px] mt-0.5">
                  Ledger Balance: <strong className="text-emerald-700">${downloadedStatement.account.balance.toFixed(2)} {downloadedStatement.account.currency}</strong>
                </span>
                <span className="text-[10px] text-slate-500 block mt-1 font-mono">
                  Generated: {new Date(downloadedStatement.generatedAt).toLocaleString()}
                </span>
              </div>
            </div>

            {/* Transactions Ledger */}
            <div className="space-y-2">
              <div className="text-xs font-semibold text-[#5B0E11] uppercase font-mono tracking-wider">
                Statement Ledger Entries ({downloadedStatement.transactions.length})
              </div>
              <div className="border border-[#EADBCE] rounded-xl overflow-hidden max-h-56 overflow-y-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-[#FAF7F2] text-[#7A6667] uppercase font-mono text-[10px] border-b border-[#EADBCE]">
                    <tr>
                      <th className="px-3 py-2">Date</th>
                      <th className="px-3 py-2">Type</th>
                      <th className="px-3 py-2">Description</th>
                      <th className="px-3 py-2 text-right">Amount</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#EADBCE]">
                    {downloadedStatement.transactions.length === 0 ? (
                      <tr>
                        <td colSpan={4} className="py-4 text-center text-slate-400">
                          No transactions recorded.
                        </td>
                      </tr>
                    ) : (
                      downloadedStatement.transactions.map((tx) => (
                        <tr key={tx.id} className="hover:bg-[#FAF7F2]/50 font-sans">
                          <td className="px-3 py-2 font-mono text-[11px] text-[#7A6667]">
                            {new Date(tx.timestamp).toLocaleDateString()}
                          </td>
                          <td className="px-3 py-2 font-mono text-[10px] font-bold">
                            {tx.type}
                          </td>
                          <td className="px-3 py-2 text-[#2B2122]">{tx.description}</td>
                          <td className="px-3 py-2 text-right font-mono font-bold text-xs">
                            ${tx.amount.toFixed(2)}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Action Bar */}
            <div className="flex items-center justify-between pt-2 border-t border-[#EADBCE]">
              <div className="text-[11px] text-[#7A6667] flex items-center space-x-1.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                <span>Statement file downloaded to your system</span>
              </div>

              <div className="flex items-center space-x-2">
                <button
                  onClick={() => {
                    if (downloadedStatement.rawText) {
                      const blob = new Blob([downloadedStatement.rawText], { type: 'text/plain;charset=utf-8' });
                      const url = URL.createObjectURL(blob);
                      const link = document.createElement('a');
                      link.href = url;
                      link.download = `Statement_${downloadedStatement.account.accountNumber}_${new Date().toISOString().substring(0, 10)}.txt`;
                      document.body.appendChild(link);
                      link.click();
                      document.body.removeChild(link);
                      URL.revokeObjectURL(url);
                    }
                  }}
                  className="px-3.5 py-2 rounded-xl bg-[#FAF7F2] hover:bg-[#F3EDE2] border border-[#DFD4C5] text-[#701318] text-xs font-semibold flex items-center space-x-1.5"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download .txt</span>
                </button>

                <button
                  onClick={() => setDownloadedStatement(null)}
                  className="px-4 py-2 rounded-xl bg-[#701318] hover:bg-[#5B0E11] text-white text-xs font-semibold"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
