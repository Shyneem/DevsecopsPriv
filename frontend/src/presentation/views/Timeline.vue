<template>
  <div class="fade-in timeline-view">
    <div class="header-actions">
      <div>
        <h1 class="title">Linea del tiempo</h1>
        <p class="subtitle">Vista infografica con linea continua y slots con o sin cambios.</p>
      </div>
    </div>

    <div v-if="statusError" class="status-banner status-error">{{ statusError }}</div>
    <div v-if="statusWarning && !warningDismissed" class="status-banner status-warning truncation-alert" role="alert">
      <div class="warning-icon-wrapper">
        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="warning-svg">
          <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>
          <line x1="12" y1="9" x2="12" y2="13"/>
          <line x1="12" y1="17" x2="12.01" y2="17"/>
        </svg>
      </div>
      <div class="warning-body">
        <strong v-if="isTruncated" class="warning-headline">Límite de eventos alcanzado (2.000 registros):</strong>
        <span class="warning-text">{{ statusWarning }}</span>
      </div>
      <button
        type="button"
        class="warning-dismiss-btn"
        @click="dismissWarning"
        title="Descartar advertencia"
        aria-label="Descartar advertencia"
      >
        ✕
      </button>
    </div>

    <TimelineFilters
      :connections="connections"
      :agent-options="agentOpts"
      :vuln-options="vulnOpts"
      :selected-connection="selectedConnection"
      :selected-agents="selectedAgents"
      :selected-vulns="selectedVulns"
      :period="period"
      :periods="periods"
      :custom-date="customDate"
      :loading="loading"
      @update:selected-connection="selectedConnection = $event"
      @update:selected-agents="selectedAgents = $event"
      @update:selected-vulns="selectedVulns = $event"
      @update:custom-date="customDate = $event"
      @connection-change="onConnectionChange"
      @set-period="setPeriod"
      @build="buildTimeline"
    />

    <TimelineKpiStrip
      :has-built="hasBuilt"
      :painted-count="paintedCount"
      :latest-snap="latestSnap"
    />

    <TimelineCanvas
      v-if="hasBuilt && visibleSlots.length > 0"
      :all-slots="allSlots"
      :visible-slots="visibleSlots"
      :painted-count="paintedCount"
      :year-label="yearLabel"
      :active-zoom="activeZoom"
      :can-move-left="canMoveLeft"
      :can-move-right="canMoveRight"
      :can-zoom-in="canZoomIn"
      :can-zoom-out="canZoomOut"
      @move-left="moveLeft"
      @move-right="moveRight"
      @zoom-in="zoomIn"
      @zoom-out="zoomOut"
      @open-slot="openModal"
    />

    <div v-else class="card empty-card">
      <div v-if="loading" class="empty-center"><p>Escaneando historial...</p></div>
      <div v-else class="empty-center">
        <h3>Sin datos para mostrar</h3>
        <p>Selecciona filtros y presiona "Generar Vista".</p>
      </div>
    </div>

    <TimelineDetailModal
      :show="modalOpen"
      :event-data="selectedEvent"
      @close="modalOpen = false"
    />
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import wazuhService from '../../application/services/wazuhService'
import useTimelineData from './timeline/useTimelineData'
import useTimelineNavigation from './timeline/useTimelineNavigation'
import { fmtYear } from './timeline/timelineFormatters'
import TimelineCanvas from './timeline/components/TimelineCanvas.vue'
import TimelineDetailModal from './timeline/components/TimelineDetailModal.vue'
import TimelineFilters from './timeline/components/TimelineFilters.vue'
import TimelineKpiStrip from './timeline/components/TimelineKpiStrip.vue'

const periods = [
  { l: '24H', v: '24h' },
  { l: '7D', v: '7d' },
  { l: '30D', v: '30d' },
  { l: 'Dia', v: 'day' },
  { l: 'Todo', v: 'all' }
]

const connections = ref([])
const agentOpts = ref([])
const vulnOpts = ref([])
const selectedConnection = ref('')
const selectedAgents = ref([])
const selectedVulns = ref([])
const period = ref('30d')
const customDate = ref(new Date().toISOString().split('T')[0])
const errorBanner = ref('')
const warningDismissed = ref(false)

const modalOpen = ref(false)
const selectedEvent = ref(null)

const getConnectionName = () => {
  const found = connections.value.find(conn => String(conn.id) === String(selectedConnection.value))
  return found?.name || ''
}

let allSlotsRef = null
const navigation = useTimelineNavigation(() => (allSlotsRef ? allSlotsRef.value.length : 0))

const {
  loading,
  hasBuilt,
  allSlots,
  paintedCount,
  latestSnap,
  errorMessage,
  warningMessage,
  isTruncated,
  build,
  fetchConnectionVulns
} = useTimelineData({
  selectedConnection,
  selectedAgents,
  selectedVulns,
  period,
  customDate,
  activeZoom: navigation.activeZoom,
  getConnectionName
})

allSlotsRef = allSlots

const {
  activeZoom,
  visibleCount,
  viewStartIndex,
  canMoveLeft,
  canMoveRight,
  canZoomIn,
  canZoomOut,
  setZoomLevel,
  zoomIn,
  zoomOut,
  moveLeft,
  moveRight,
  jumpToEnd
} = navigation

const visibleSlots = computed(() =>
  allSlots.value.slice(viewStartIndex.value, viewStartIndex.value + visibleCount.value)
)

const yearLabel = computed(() => {
  if (!visibleSlots.value.length) return ''
  const start = fmtYear(visibleSlots.value[0].startMs)
  const end = fmtYear(visibleSlots.value[visibleSlots.value.length - 1].startMs)
  return start === end ? start : `${start} - ${end}`
})

const setPeriod = value => {
  period.value = value
}

const onConnectionChange = async () => {
  selectedAgents.value = []
  selectedVulns.value = []
  agentOpts.value = []
  vulnOpts.value = []
  errorBanner.value = ''
  warningDismissed.value = false

  if (!selectedConnection.value) return

  try {
    const data = await fetchConnectionVulns()
    const agents = new Set()
    const vulns = new Set()

    data.forEach(vuln => {
      if (vuln.agent_name) agents.add(vuln.agent_name)
      if (vuln.cve_id) vulns.add(vuln.cve_id)
    })

    agentOpts.value = Array.from(agents).sort()
    vulnOpts.value = Array.from(vulns).sort()
  } catch (error) {
    console.error(error)
    errorBanner.value = 'No se pudieron cargar agentes y CVEs para la conexion seleccionada.'
  }
}

const buildTimeline = async () => {
  errorBanner.value = ''
  warningDismissed.value = false
  try {
    const { initialZoom } = await build()
    setZoomLevel(initialZoom)
    jumpToEnd()
  } catch (error) {
    console.error(error)
  }
}

const openModal = slot => {
  selectedEvent.value = slot
  modalOpen.value = true
}

onMounted(async () => {
  try {
    const response = await wazuhService.getConnections()
    connections.value = Array.isArray(response.data) ? response.data : []
  } catch (error) {
    console.error(error)
    errorBanner.value = 'No se pudieron cargar las conexiones Wazuh.'
  }
})

const statusError = computed(() => errorBanner.value || errorMessage.value)
const statusWarning = computed(() => warningMessage.value)

const dismissWarning = () => {
  warningDismissed.value = true
}
</script>

<style scoped>
.timeline-view {
  display: flex;
  flex-direction: column;
  gap: 0.85rem;
}

.status-banner {
  border-radius: var(--radius-sm);
  padding: 0.7rem 0.9rem;
  border: 1px solid var(--border);
  font-size: 0.85rem;
  font-weight: 600;
}

.status-error {
  color: var(--danger);
  background: var(--danger-bg);
  border-color: rgba(220, 38, 38, 0.3);
}

.status-warning {
  color: var(--warning);
  background: var(--warning-bg);
  border-color: rgba(217, 119, 6, 0.25);
}

.truncation-alert {
  display: flex;
  align-items: flex-start;
  gap: 0.75rem;
  background: rgba(217, 119, 6, 0.12);
  border: 1px solid rgba(217, 119, 6, 0.4);
  box-shadow: 0 2px 8px rgba(217, 119, 6, 0.08);
  padding: 0.85rem 1rem;
}

.warning-icon-wrapper {
  display: flex;
  align-items: center;
  color: var(--warning);
  flex-shrink: 0;
  margin-top: 1px;
}

.warning-body {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 0.2rem;
  color: #92400e;
  font-weight: 500;
  line-height: 1.45;
}

.warning-headline {
  font-weight: 700;
  color: #78350f;
  font-size: 0.9rem;
}

.warning-dismiss-btn {
  background: transparent;
  border: none;
  color: var(--warning);
  cursor: pointer;
  font-size: 1.1rem;
  font-weight: bold;
  padding: 0 0.4rem;
  line-height: 1;
  opacity: 0.75;
  transition: opacity 0.2s, background 0.2s;
  border-radius: 4px;
}

.warning-dismiss-btn:hover {
  opacity: 1;
  background: rgba(217, 119, 6, 0.2);
}

.empty-card {
  min-height: 240px;
  display: flex;
  justify-content: center;
  align-items: center;
  text-align: center;
}

.empty-center p {
  color: var(--text-muted);
}
</style>
