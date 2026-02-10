'use client'

import { useRouter } from 'next/navigation'
import { Sparkles, Play, Download, Loader2, Terminal, Settings, Shield } from 'lucide-react'
import { Toggle } from '@/components/ui'
import type { ReconStatus, GvmStatus } from '@/lib/recon-types'
import styles from './GraphToolbar.module.css'

interface GraphToolbarProps {
  projectId: string
  is3D: boolean
  showLabels: boolean
  onToggle3D: (value: boolean) => void
  onToggleLabels: (value: boolean) => void
  onToggleAI?: () => void
  isAIOpen?: boolean
  // Target info
  targetDomain?: string
  subdomainList?: string[]
  // Recon props
  onStartRecon?: () => void
  onDownloadJSON?: () => void
  onToggleLogs?: () => void
  reconStatus?: ReconStatus
  hasReconData?: boolean
  isLogsOpen?: boolean
  // GVM props
  onStartGvm?: () => void
  onDownloadGvmJSON?: () => void
  onToggleGvmLogs?: () => void
  gvmStatus?: GvmStatus
  hasGvmData?: boolean
  isGvmLogsOpen?: boolean
}

export function GraphToolbar({
  projectId,
  is3D,
  showLabels,
  onToggle3D,
  onToggleLabels,
  onToggleAI,
  isAIOpen = false,
  // Target info
  targetDomain,
  subdomainList = [],
  // Recon props
  onStartRecon,
  onDownloadJSON,
  onToggleLogs,
  reconStatus = 'idle',
  hasReconData = false,
  isLogsOpen = false,
  // GVM props
  onStartGvm,
  onDownloadGvmJSON,
  onToggleGvmLogs,
  gvmStatus = 'idle',
  hasGvmData = false,
  isGvmLogsOpen = false,
}: GraphToolbarProps) {
  const router = useRouter()
  const isReconRunning = reconStatus === 'running' || reconStatus === 'starting'
  const isGvmRunning = gvmStatus === 'running' || gvmStatus === 'starting'

  const handleOpenSettings = () => {
    if (projectId) {
      router.push(`/projects/${projectId}/settings`)
    }
  }

  return (
    <div className={styles.toolbar}>
      <div className={styles.section}>
        <span className={styles.sectionLabel}>View Mode</span>
        <Toggle
          checked={is3D}
          onChange={onToggle3D}
          labelOff="2D"
          labelOn="3D"
          aria-label="Toggle 2D/3D view"
        />
      </div>

      <div className={styles.divider} />

      <div className={styles.section}>
        <span className={styles.sectionLabel}>Labels</span>
        <Toggle
          checked={showLabels}
          onChange={onToggleLabels}
          labelOff="Off"
          labelOn="On"
          aria-label="Toggle labels"
        />
      </div>

      {targetDomain && (
        <>
          <div className={styles.divider} />
          <div className={styles.targetSection}>
            {subdomainList.length > 0 && (
              <div className={styles.subdomainWrapper}>
                <span className={styles.subdomainList}>
                  {subdomainList.join(', ')}
                </span>
                <div className={styles.subdomainTooltip}>
                  {subdomainList.join(', ')}
                </div>
              </div>
            )}
            <span className={styles.targetDomain}>{targetDomain}</span>
          </div>
        </>
      )}

      <div className={styles.spacer} />

      {/* Recon Actions */}
      {projectId && (
        <>
          <button
            className={`${styles.reconButton} ${isReconRunning ? styles.reconButtonActive : ''}`}
            onClick={onStartRecon}
            disabled={isReconRunning}
            title={isReconRunning ? 'Recon in progress...' : 'Start Reconnaissance'}
          >
            {isReconRunning ? (
              <Loader2 size={14} className={styles.spinner} />
            ) : (
              <Play size={14} />
            )}
            <span>{isReconRunning ? 'Running...' : 'Start Recon'}</span>
          </button>

          {isReconRunning && (
            <button
              className={`${styles.logsButton} ${isLogsOpen ? styles.logsButtonActive : ''}`}
              onClick={onToggleLogs}
              title="View Logs"
            >
              <Terminal size={14} />
            </button>
          )}

          <button
            className={styles.downloadButton}
            onClick={onDownloadJSON}
            disabled={!hasReconData || isReconRunning}
            title={hasReconData ? 'Download Recon JSON' : 'No data available'}
          >
            <Download size={14} />
          </button>

          <div className={styles.divider} />

          {/* GVM Scan Actions */}
          <button
            className={`${styles.gvmButton} ${isGvmRunning ? styles.gvmButtonActive : ''}`}
            onClick={onStartGvm}
            disabled={isGvmRunning || !hasReconData}
            title={
              !hasReconData
                ? 'Run recon first'
                : isGvmRunning
                ? 'GVM scan in progress...'
                : 'Start GVM Vulnerability Scan'
            }
          >
            {isGvmRunning ? (
              <Loader2 size={14} className={styles.spinner} />
            ) : (
              <Shield size={14} />
            )}
            <span>{isGvmRunning ? 'Scanning...' : 'GVM Scan'}</span>
          </button>

          {isGvmRunning && (
            <button
              className={`${styles.logsButton} ${isGvmLogsOpen ? styles.logsButtonActive : ''}`}
              onClick={onToggleGvmLogs}
              title="View GVM Logs"
            >
              <Terminal size={14} />
            </button>
          )}

          <button
            className={styles.downloadButton}
            onClick={onDownloadGvmJSON}
            disabled={!hasGvmData || isGvmRunning}
            title={hasGvmData ? 'Download GVM JSON' : 'No GVM data available'}
          >
            <Download size={14} />
          </button>

          <div className={styles.divider} />
        </>
      )}

      <div className={styles.projectBadge}>
        <span className={styles.projectLabel}>Project:</span>
        <span className={styles.projectId}>{projectId}</span>
        <button
          className={styles.settingsButton}
          onClick={handleOpenSettings}
          title="Project Settings"
          aria-label="Open project settings"
        >
          <Settings size={14} />
        </button>
      </div>

      <div className={styles.divider} />

      <button
        className={`${styles.aiButton} ${isAIOpen ? styles.aiButtonActive : ''}`}
        onClick={onToggleAI}
        aria-label="Toggle RedAmon Agent"
        aria-expanded={isAIOpen}
        title="RedAmon Agent"
      >
        <Sparkles size={14} />
        <span>RedAmon Agent</span>
      </button>
    </div>
  )
}
