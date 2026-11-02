<template>
  <div class="card timeline-card">
    <div class="tl-toolbar">
      <div class="tl-toolbar-left">
        <span class="tl-year">{{ yearLabel }}</span>

        <div class="view-mode-toggle" role="tablist" aria-label="Modo de visualización de línea de tiempo">
          <button
            type="button"
            role="tab"
            class="vmt-btn"
            :class="{ active: currentViewMode === 'global' }"
            :aria-selected="currentViewMode === 'global'"
            @click="setViewMode('global')"
            title="Vista general acumulada por intervalos de tiempo"
          >
            <span class="vmt-icon">📊</span> Vista General
          </button>
          <button
            type="button"
            role="tab"
            class="vmt-btn"
            :class="{ active: currentViewMode === 'agent' }"
            :aria-selected="currentViewMode === 'agent'"
            @click="setViewMode('agent')"
            title="Línea temporal desglosada por equipos / agentes"
          >
            <span class="vmt-icon">🖥️</span> Por Agente
            <span v-if="agentSummaryList.length" class="vmt-badge">{{ agentSummaryList.length }}</span>
          </button>
          <button
            type="button"
            role="tab"
            class="vmt-btn"
            :class="{ active: currentViewMode === 'cve' }"
            :aria-selected="currentViewMode === 'cve'"
            @click="setViewMode('cve')"
            title="Línea temporal desglosada por vulnerabilidades (CVE)"
          >
            <span class="vmt-icon">🛡️</span> Por CVE
            <span v-if="cveSummaryList.length" class="vmt-badge">{{ cveSummaryList.length }}</span>
          </button>
        </div>
      </div>

      <div class="tl-toolbar-right">
        <button class="btn btn-outline btn-icon" @click="emit('move-left')" :disabled="!canMoveLeft" title="Desplazar a la izquierda">◀</button>
        <button class="btn btn-outline btn-icon" @click="emit('zoom-out')" :disabled="!canZoomOut" title="Alejar zoom">-</button>
        <span class="zoom-badge">{{ activeZoom.label }}</span>
        <button class="btn btn-outline btn-icon" @click="emit('zoom-in')" :disabled="!canZoomIn" title="Acercar zoom">+</button>
        <button class="btn btn-outline btn-icon" @click="emit('move-right')" :disabled="!canMoveRight" title="Desplazar a la derecha">▶</button>
      </div>
    </div>

    <!-- 1. VISTA GENERAL (INFOGRÁFICA ORIGINAL) -->
    <div v-if="currentViewMode === 'global'" class="ig-stage" :style="stageStyle">
      <div class="ig-label-row">
        <div v-for="slot in visibleSlots" :key="`l-${slot.startMs}`" class="ig-label-slot">
          <span v-if="slot.painted" class="ig-label" :class="slot.type">{{ badge(slot.type) }}</span>
        </div>
      </div>

      <div class="ig-track-wrap">
        <div class="ig-segments">
          <div
            v-for="slot in visibleSlots"
            :key="`s-${slot.startMs}`"
            class="ig-segment"
            :class="slot.painted ? slot.type : 'empty'"
          >
            <span class="segment-date">{{ slot.tickLabel }}</span>
          </div>
        </div>
      </div>

      <div class="ig-cards-row">
        <div v-for="slot in visibleSlots" :key="`c-${slot.startMs}`" class="ig-card-slot">
          <button v-if="slot.painted" class="event-card" :class="slot.type" @click="emit('open-slot', slot)">
            <div class="card-top">{{ slot.cardLabel }}</div>
            <div class="card-stats">
              <span>Total: <strong>{{ slot.total }}</strong></span>
              <span class="danger">Pendientes: <strong>{{ slot.pending }}</strong></span>
              <span class="success">Resueltos: <strong>{{ slot.resolved }}</strong></span>
            </div>
          </button>
        </div>
      </div>
    </div>

    <!-- 2. VISTA POR AGENTE (SWIMLANES TEMPORALES) -->
    <div v-else-if="currentViewMode === 'agent'" class="swimlane-view">
      <div class="swimlane-subbar">
        <div class="search-box">
          <input
            type="text"
            v-model="agentSearch"
            placeholder="Buscar equipo / agente..."
            class="swimlane-input"
          />
          <span class="search-counter">
            {{ filteredAgents.length }} de {{ agentSummaryList.length }} agentes
          </span>
        </div>

        <div class="swimlane-legend">
          <span class="legend-item"><span class="legend-dot detection"></span> Nueva</span>
          <span class="legend-item"><span class="legend-dot resolution"></span> Resuelta</span>
          <span class="legend-item"><span class="legend-dot mixed"></span> Mixto</span>
          <span class="legend-separator">|</span>
          <span class="legend-pill sev-critical">Crítica</span>
          <span class="legend-pill sev-high">Alta</span>
          <span class="legend-pill sev-medium">Media</span>
          <span class="legend-pill sev-low">Baja</span>
        </div>
      </div>

      <div class="swimlane-table-wrapper custom-scroll">
        <table class="swimlane-table">
          <thead>
            <tr>
              <th class="th-entity sticky-col">Equipo / Agente</th>
              <th
                v-for="slot in visibleSlots"
                :key="`ah-${slot.startMs}`"
                class="th-slot"
                :class="{ 'has-events': slot.painted }"
              >
                <div class="th-slot-title">{{ slot.tickLabel }}</div>
                <div class="th-slot-sub">{{ activeZoom.slotHours >= 24 ? fmtYear(slot.startMs) : fmtHour(slot.startMs) }}</div>
              </th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="agent in filteredAgents" :key="agent.name" class="swimlane-row">
              <td class="td-entity sticky-col">
                <div class="entity-info">
                  <div class="entity-name-row">
                    <span class="entity-icon">🖥️</span>
                    <strong class="entity-name" :title="agent.name">{{ agent.name }}</strong>
                  </div>
                  <div class="entity-meta">
                    <span class="meta-tag active-tag" title="Vulnerabilidades pendientes">{{ agent.activeVulns }} activas</span>
                    <span class="meta-tag resolved-tag" title="Vulnerabilidades resueltas">{{ agent.resolvedVulns }} resueltas</span>
                  </div>
                  <div class="entity-sev-dots" v-if="agent.activeVulns > 0">
                    <span v-if="agent.severities.critical" class="sev-count critical" title="Críticas">
                      {{ agent.severities.critical }} C
                    </span>
                    <span v-if="agent.severities.high" class="sev-count high" title="Altas">
                      {{ agent.severities.high }} A
                    </span>
                    <span v-if="agent.severities.medium" class="sev-count medium" title="Medias">
                      {{ agent.severities.medium }} M
                    </span>
                    <span v-if="agent.severities.low" class="sev-count low" title="Bajas">
                      {{ agent.severities.low }} B
                    </span>
                  </div>
                </div>
              </td>

              <td
                v-for="slot in visibleSlots"
                :key="`as-${agent.name}-${slot.startMs}`"
                class="td-slot-cell"
              >
                <button
                  v-if="slot.byAgent && slot.byAgent[agent.name]"
                  type="button"
                  class="lane-event-card"
                  :class="slot.byAgent[agent.name].type"
                  @click="emit('open-slot', slot, { agent: agent.name })"
                  :title="`Ver ${slot.byAgent[agent.name].total} evento(s) en ${agent.name} durante ${slot.cardLabel}`"
                >
                  <div class="card-lane-top">
                    <span class="lane-badge" :class="slot.byAgent[agent.name].type">
                      {{ badge(slot.byAgent[agent.name].type) }}
                    </span>
                    <span class="lane-count">
                      {{ slot.byAgent[agent.name].total }} {{ slot.byAgent[agent.name].total === 1 ? 'vuln' : 'vulns' }}
                    </span>
                  </div>

                  <div class="card-lane-cves">
                    <span
                      v-for="cve in slot.byAgent[agent.name].cves.slice(0, 2)"
                      :key="cve"
                      class="cve-chip"
                      :class="getCveSeverityClass(cve)"
                    >
                      {{ cve }}
                    </span>
                    <span
                      v-if="slot.byAgent[agent.name].cves.length > 2"
                      class="cve-chip-more"
                    >
                      +{{ slot.byAgent[agent.name].cves.length - 2 }}
                    </span>
                  </div>
                </button>

                <div v-else class="lane-connector">
                  <span class="connector-line"></span>
                  <span class="connector-dot"></span>
                </div>
              </td>
            </tr>

            <tr v-if="filteredAgents.length === 0">
              <td :colspan="visibleSlots.length + 1" class="swimlane-empty">
                No se encontraron agentes que coincidan con la búsqueda.
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- 3. VISTA POR CVE (SWIMLANES POR VULNERABILIDAD) -->
    <div v-else-if="currentViewMode === 'cve'" class="swimlane-view">
      <div class="swimlane-subbar">
        <div class="search-box">
          <input
            type="text"
            v-model="cveSearch"
            placeholder="Buscar por CVE o software..."
            class="swimlane-input"
          />
          <select v-model="cveSeverityFilter" class="swimlane-select">
            <option value="">Todas las severidades</option>
            <option value="critical">Crítica</option>
            <option value="high">Alta</option>
            <option value="medium">Media</option>
            <option value="low">Baja</option>
          </select>
          <span class="search-counter">
            {{ filteredCves.length }} de {{ cveSummaryList.length }} CVEs
          </span>
        </div>

        <div class="swimlane-legend">
          <span class="legend-item"><span class="legend-dot detection"></span> Detectada</span>
          <span class="legend-item"><span class="legend-dot resolution"></span> Resuelta</span>
          <span class="legend-item"><span class="legend-dot mixed"></span> Mixto</span>
        </div>
      </div>

      <div class="swimlane-table-wrapper custom-scroll">
        <table class="swimlane-table">
          <thead>
            <tr>
              <th class="th-entity sticky-col">Vulnerabilidad (CVE)</th>
              <th
                v-for="slot in visibleSlots"
                :key="`ch-${slot.startMs}`"
                class="th-slot"
                :class="{ 'has-events': slot.painted }"
              >
                <div class="th-slot-title">{{ slot.tickLabel }}</div>
                <div class="th-slot-sub">{{ activeZoom.slotHours >= 24 ? fmtYear(slot.startMs) : fmtHour(slot.startMs) }}</div>
              </th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="cve in filteredCves" :key="cve.cve_id" class="swimlane-row">
              <td class="td-entity sticky-col">
                <div class="entity-info">
                  <div class="entity-cve-header">
                    <span class="sev-tag" :class="cve.severityCategory">
                      {{ getSeverityLabel(cve.severity) }}
                    </span>
                    <strong class="entity-cve-code"><code>{{ cve.cve_id }}</code></strong>
                  </div>
                  <div class="entity-meta">
                    <span class="meta-tag agent-tag" title="Equipos afectados">
                      👥 {{ cve.affectedAgents.length }} {{ cve.affectedAgents.length === 1 ? 'agente' : 'agentes' }}
                    </span>
                    <span
                      class="meta-tag"
                      :class="cve.activeOccurrences > 0 ? 'active-tag' : 'resolved-tag'"
                    >
                      {{ cve.activeOccurrences > 0 ? `${cve.activeOccurrences} activas` : 'Resuelta' }}
                    </span>
                  </div>
                  <div v-if="cve.package_name" class="entity-package" :title="cve.package_name">
                    📦 {{ cve.package_name }}
                  </div>
                </div>
              </td>

              <td
                v-for="slot in visibleSlots"
                :key="`cs-${cve.cve_id}-${slot.startMs}`"
                class="td-slot-cell"
              >
                <button
                  v-if="slot.byCve && slot.byCve[cve.cve_id]"
                  type="button"
                  class="lane-event-card"
                  :class="slot.byCve[cve.cve_id].type"
                  @click="emit('open-slot', slot, { cve: cve.cve_id })"
                  :title="`Ver detalle de ${cve.cve_id} en ${slot.cardLabel}`"
                >
                  <div class="card-lane-top">
                    <span class="lane-badge" :class="slot.byCve[cve.cve_id].type">
                      {{ badge(slot.byCve[cve.cve_id].type) }}
                    </span>
                    <span class="lane-count">
                      {{ slot.byCve[cve.cve_id].agents.length }} {{ slot.byCve[cve.cve_id].agents.length === 1 ? 'host' : 'hosts' }}
                    </span>
                  </div>

                  <div class="card-lane-hosts">
                    <span
                      v-for="agent in slot.byCve[cve.cve_id].agents.slice(0, 2)"
                      :key="agent"
                      class="host-chip"
                      :title="agent"
                    >
                      {{ agent }}
                    </span>
                    <span
                      v-if="slot.byCve[cve.cve_id].agents.length > 2"
                      class="host-chip-more"
                    >
                      +{{ slot.byCve[cve.cve_id].agents.length - 2 }}
                    </span>
                  </div>
                </button>

                <div v-else class="lane-connector">
                  <span class="connector-line"></span>
                  <span class="connector-dot"></span>
                </div>
              </td>
            </tr>

            <tr v-if="filteredCves.length === 0">
              <td :colspan="visibleSlots.length + 1" class="swimlane-empty">
                No se encontraron vulnerabilidades que coincidan con los filtros aplicados.
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, ref, watch } from 'vue'
import {
  badge,
  fmtHour,
  fmtYear,
  getSeverityCategory,
  getSeverityLabel
} from '../timelineFormatters'

const props = defineProps({
  allSlots: { type: Array, required: true },
  visibleSlots: { type: Array, required: true },
  paintedCount: { type: Number, required: true },
  yearLabel: { type: String, default: '' },
  activeZoom: { type: Object, required: true },
  canMoveLeft: { type: Boolean, default: false },
  canMoveRight: { type: Boolean, default: false },
  canZoomIn: { type: Boolean, default: false },
  canZoomOut: { type: Boolean, default: false },
  agentSummaryList: { type: Array, default: () => [] },
  cveSummaryList: { type: Array, default: () => [] },
  viewMode: { type: String, default: 'global' }
})

const emit = defineEmits([
  'move-left',
  'move-right',
  'zoom-in',
  'zoom-out',
  'open-slot',
  'update:viewMode'
])

const currentViewMode = ref(props.viewMode || 'global')
const agentSearch = ref('')
const cveSearch = ref('')
const cveSeverityFilter = ref('')

watch(
  () => props.viewMode,
  newVal => {
    if (newVal) currentViewMode.value = newVal
  }
)

const setViewMode = mode => {
  currentViewMode.value = mode
  emit('update:viewMode', mode)
}

const stageStyle = computed(() => ({
  '--slot-count': String(Math.max(1, props.visibleSlots.length))
}))

const filteredAgents = computed(() => {
  if (!agentSearch.value.trim()) return props.agentSummaryList
  const q = agentSearch.value.toLowerCase().trim()
  return props.agentSummaryList.filter(agent =>
    agent.name.toLowerCase().includes(q)
  )
})

const filteredCves = computed(() => {
  return props.cveSummaryList.filter(cve => {
    const matchesSearch =
      !cveSearch.value.trim() ||
      cve.cve_id.toLowerCase().includes(cveSearch.value.toLowerCase().trim()) ||
      (cve.package_name &&
        cve.package_name.toLowerCase().includes(cveSearch.value.toLowerCase().trim()))

    const matchesSeverity =
      !cveSeverityFilter.value ||
      cve.severityCategory === cveSeverityFilter.value

    return matchesSearch && matchesSeverity
  })
})

const cveSeverityMap = computed(() => {
  const map = new Map()
  props.cveSummaryList.forEach(c => {
    map.set(c.cve_id, c.severityCategory)
  })
  return map
})

const getCveSeverityClass = cveId => {
  const cat = cveSeverityMap.value.get(cveId) || 'medium'
  return `sev-${cat}`
}
</script>

<style scoped>
.timeline-card {
  padding: 0;
  overflow: hidden;
  background: var(--bg-panel);
}

.tl-toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.85rem 1.2rem;
  border-bottom: 1px solid var(--border);
  background: var(--bg-hover);
  flex-wrap: wrap;
  gap: 0.75rem;
}

.tl-toolbar-left {
  display: flex;
  gap: 1.2rem;
  align-items: center;
  flex-wrap: wrap;
}

.tl-year {
  font-weight: 800;
  font-size: 0.95rem;
  color: var(--text-main);
  white-space: nowrap;
}

/* Selector de Modo de Vista */
.view-mode-toggle {
  display: flex;
  background: var(--bg-dark);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 3px;
  gap: 3px;
}

.vmt-btn {
  display: flex;
  align-items: center;
  gap: 0.35rem;
  padding: 0.38rem 0.75rem;
  border: none;
  background: transparent;
  color: var(--text-muted);
  border-radius: calc(var(--radius-sm) - 2px);
  font-size: 0.78rem;
  font-weight: 700;
  cursor: pointer;
  transition: all 0.18s ease;
  white-space: nowrap;
}

.vmt-btn:hover {
  color: var(--text-main);
  background: rgba(255, 255, 255, 0.05);
}

.vmt-btn.active {
  background: var(--primary);
  color: #fff;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12);
}

.vmt-icon {
  font-size: 0.85rem;
}

.vmt-badge {
  background: rgba(255, 255, 255, 0.25);
  color: inherit;
  padding: 0.1rem 0.35rem;
  border-radius: 999px;
  font-size: 0.65rem;
  font-weight: 800;
}

.vmt-btn:not(.active) .vmt-badge {
  background: var(--border);
  color: var(--text-muted);
}

.tl-toolbar-right {
  display: flex;
  align-items: center;
  gap: 0.4rem;
}

.zoom-badge {
  min-width: 52px;
  text-align: center;
  font-weight: 800;
  font-size: 0.78rem;
  color: var(--text-muted);
}

.btn-outline {
  background: transparent;
  color: var(--text-muted);
  border: 1px solid var(--border);
}

.btn-outline:hover:not(:disabled) {
  border-color: var(--primary);
  color: var(--primary);
}

.btn-icon {
  width: 34px;
  height: 34px;
  padding: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: var(--radius-sm);
}

/* 1. ESTILOS DE LA VISTA GENERAL */
.ig-stage {
  position: relative;
  padding: 2.2rem 1.2rem 1.5rem;
  background: linear-gradient(180deg, #f8f7f0 0%, #f1f4ee 100%);
  overflow-x: auto;
}

.ig-label-row,
.ig-cards-row,
.ig-segments {
  display: grid;
  grid-template-columns: repeat(var(--slot-count), minmax(90px, 1fr));
  gap: 0.75rem;
}

.ig-label-slot,
.ig-card-slot {
  display: flex;
  justify-content: center;
}

.ig-label {
  padding: 0.35rem 0.6rem;
  border-radius: 999px;
  font-size: 0.68rem;
  font-weight: 800;
  text-transform: uppercase;
  letter-spacing: 0.03em;
  color: #fff;
}

.ig-label.detection { background: #6ea42a; }
.ig-label.resolution { background: #059669; }
.ig-label.mixed { background: #d97706; }

.ig-track-wrap { position: relative; margin-top: 1rem; }
.ig-segments { align-items: center; }

.ig-segment {
  min-height: 30px;
  border-radius: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  border: 1px solid rgba(17, 24, 39, 0.08);
  background: #d1d5db;
}

.ig-segment.empty { opacity: 0.45; }
.ig-segment.detection { background: #6ea42a; color: #fff; }
.ig-segment.resolution { background: #059669; color: #fff; }
.ig-segment.mixed { background: #d97706; color: #fff; }

.segment-date { font-size: 0.72rem; font-weight: 700; }

.ig-cards-row { margin-top: 1.6rem; }

.event-card {
  width: 100%;
  max-width: 160px;
  min-height: 138px;
  border: none;
  border-radius: var(--radius-sm);
  text-align: left;
  color: #fff;
  cursor: pointer;
  box-shadow: var(--shadow-sm);
  transition: var(--transition);
}

.event-card:hover { transform: translateY(-4px); box-shadow: var(--shadow-md); }
.event-card.detection { background: #6ea42a; }
.event-card.resolution { background: #059669; }
.event-card.mixed { background: #d97706; }

.card-top {
  font-size: 0.73rem;
  font-weight: 800;
  letter-spacing: 0.02em;
  border-bottom: 1px solid rgba(255, 255, 255, 0.35);
  padding: 0.7rem;
}

.card-stats {
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
  padding: 0.7rem;
  font-size: 0.72rem;
}

.card-stats .danger { color: #fee2e2; }
.card-stats .success { color: #dcfce7; }

/* 2 y 3. ESTILOS DE SWIMLANES (POR AGENTE Y POR CVE) */
.swimlane-view {
  background: var(--bg-panel);
  display: flex;
  flex-direction: column;
}

.swimlane-subbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.75rem 1.2rem;
  background: var(--bg-dark);
  border-bottom: 1px solid var(--border);
  gap: 1rem;
  flex-wrap: wrap;
}

.search-box {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  flex: 1;
  max-width: 580px;
}

.swimlane-input,
.swimlane-select {
  padding: 0.45rem 0.8rem;
  border: 1px solid var(--border);
  background: var(--bg-panel);
  border-radius: var(--radius-sm);
  color: var(--text-main);
  font-size: 0.8rem;
}

.swimlane-input {
  flex: 1;
  min-width: 180px;
}

.search-counter {
  font-size: 0.75rem;
  color: var(--text-muted);
  font-weight: 600;
  white-space: nowrap;
}

.swimlane-legend {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  font-size: 0.72rem;
  color: var(--text-muted);
  font-weight: 600;
  flex-wrap: wrap;
}

.legend-item {
  display: flex;
  align-items: center;
  gap: 0.3rem;
}

.legend-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  display: inline-block;
}

.legend-dot.detection { background: #6ea42a; }
.legend-dot.resolution { background: #059669; }
.legend-dot.mixed { background: #d97706; }

.legend-separator {
  color: var(--border);
  margin: 0 0.2rem;
}

.legend-pill {
  padding: 0.15rem 0.45rem;
  border-radius: 4px;
  font-size: 0.68rem;
  font-weight: 700;
}

.swimlane-table-wrapper {
  overflow-x: auto;
  max-height: 650px;
}

.swimlane-table {
  width: 100%;
  border-collapse: separate;
  border-spacing: 0;
  font-size: 0.8rem;
}

/* Header de Swimlanes */
.th-entity {
  width: 250px;
  min-width: 250px;
  padding: 0.75rem 1rem;
  background: var(--bg-hover);
  color: var(--text-muted);
  text-align: left;
  font-size: 0.7rem;
  font-weight: 800;
  text-transform: uppercase;
  border-bottom: 2px solid var(--border);
  border-right: 1px solid var(--border);
}

.th-slot {
  min-width: 140px;
  padding: 0.65rem 0.5rem;
  background: var(--bg-hover);
  color: var(--text-main);
  text-align: center;
  border-bottom: 2px solid var(--border);
  border-right: 1px solid rgba(0, 0, 0, 0.06);
}

.th-slot.has-events {
  background: rgba(110, 164, 42, 0.08);
}

.th-slot-title {
  font-weight: 800;
  font-size: 0.78rem;
}

.th-slot-sub {
  font-size: 0.68rem;
  color: var(--text-muted);
  font-weight: 500;
}

/* Sticky Column */
.sticky-col {
  position: sticky;
  left: 0;
  z-index: 5;
  background: var(--bg-panel);
}

thead .sticky-col {
  z-index: 10;
  background: var(--bg-hover);
}

/* Body de Swimlanes */
.swimlane-row:hover .sticky-col {
  background: var(--bg-hover);
}

.swimlane-row:hover td {
  background: rgba(0, 0, 0, 0.015);
}

.td-entity {
  padding: 0.85rem 1rem;
  border-bottom: 1px solid var(--border);
  border-right: 1px solid var(--border);
  vertical-align: middle;
}

.entity-info {
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
}

.entity-name-row {
  display: flex;
  align-items: center;
  gap: 0.4rem;
}

.entity-icon {
  font-size: 0.95rem;
}

.entity-name {
  font-size: 0.85rem;
  color: var(--text-main);
  font-weight: 700;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  max-width: 190px;
}

.entity-cve-header {
  display: flex;
  align-items: center;
  gap: 0.45rem;
}

.entity-cve-code code {
  font-size: 0.82rem;
  color: var(--text-main);
  font-weight: 700;
}

.entity-meta {
  display: flex;
  gap: 0.4rem;
  flex-wrap: wrap;
}

.meta-tag {
  font-size: 0.68rem;
  font-weight: 700;
  padding: 0.12rem 0.4rem;
  border-radius: 4px;
}

.active-tag {
  background: #fee2e2;
  color: #991b1b;
}

.resolved-tag {
  background: #dcfce7;
  color: #166534;
}

.agent-tag {
  background: #e0e7ff;
  color: #3730a3;
}

.entity-sev-dots {
  display: flex;
  gap: 0.3rem;
  flex-wrap: wrap;
}

.sev-count {
  font-size: 0.65rem;
  font-weight: 800;
  padding: 0.1rem 0.35rem;
  border-radius: 3px;
  color: #fff;
}

.sev-count.critical { background: #dc2626; }
.sev-count.high { background: #ea580c; }
.sev-count.medium { background: #eab308; color: #854d0e; }
.sev-count.low { background: #3b82f6; }

.entity-package {
  font-size: 0.68rem;
  color: var(--text-muted);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  max-width: 210px;
}

/* Celdas de Slots en Swimlane */
.td-slot-cell {
  padding: 0.5rem 0.4rem;
  border-bottom: 1px solid var(--border);
  border-right: 1px solid rgba(0, 0, 0, 0.05);
  text-align: center;
  vertical-align: middle;
}

/* Tarjeta interactiva de evento en el swimlane */
.lane-event-card {
  width: 100%;
  padding: 0.5rem 0.6rem;
  border-radius: var(--radius-sm);
  border: 1px solid transparent;
  background: #f3f4f6;
  cursor: pointer;
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
  text-align: left;
  transition: all 0.18s ease;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.06);
}

.lane-event-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.12);
}

.lane-event-card.detection {
  border-color: rgba(110, 164, 42, 0.4);
  background: linear-gradient(135deg, #f7fcee 0%, #edf7dc 100%);
}

.lane-event-card.resolution {
  border-color: rgba(5, 150, 105, 0.4);
  background: linear-gradient(135deg, #ecfdf5 0%, #d1fae5 100%);
}

.lane-event-card.mixed {
  border-color: rgba(217, 119, 6, 0.4);
  background: linear-gradient(135deg, #fffbeb 0%, #fef3c7 100%);
}

.card-lane-top {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.lane-badge {
  font-size: 0.62rem;
  font-weight: 800;
  text-transform: uppercase;
  padding: 0.12rem 0.4rem;
  border-radius: 999px;
  color: #fff;
}

.lane-badge.detection { background: #6ea42a; }
.lane-badge.resolution { background: #059669; }
.lane-badge.mixed { background: #d97706; }

.lane-count {
  font-size: 0.68rem;
  font-weight: 700;
  color: var(--text-muted);
}

.card-lane-cves,
.card-lane-hosts {
  display: flex;
  gap: 0.25rem;
  flex-wrap: wrap;
}

.cve-chip,
.host-chip {
  font-size: 0.64rem;
  font-weight: 700;
  padding: 0.1rem 0.35rem;
  border-radius: 4px;
  white-space: nowrap;
  font-family: monospace;
}

.cve-chip.sev-critical {
  background: #fee2e2;
  color: #991b1b;
  border: 1px solid #fca5a5;
}

.cve-chip.sev-high {
  background: #ffedd5;
  color: #9a3412;
  border: 1px solid #fdba74;
}

.cve-chip.sev-medium {
  background: #fef9c3;
  color: #854d0e;
  border: 1px solid #fde047;
}

.cve-chip.sev-low {
  background: #dbeafe;
  color: #1e40af;
  border: 1px solid #bfdbfe;
}

.host-chip {
  background: #f3f4f6;
  color: #374151;
  border: 1px solid #d1d5db;
  font-family: inherit;
}

.cve-chip-more,
.host-chip-more {
  font-size: 0.62rem;
  font-weight: 800;
  color: var(--text-muted);
  align-self: center;
}

/* Conector vacío cuando no hay evento en el slot */
.lane-connector {
  position: relative;
  display: flex;
  align-items: center;
  justify-content: center;
  height: 28px;
}

.connector-line {
  position: absolute;
  left: 0;
  right: 0;
  height: 2px;
  background: rgba(0, 0, 0, 0.08);
}

.connector-dot {
  position: relative;
  z-index: 1;
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: #d1d5db;
}

/* Badges de severidad */
.sev-tag {
  font-size: 0.63rem;
  font-weight: 800;
  text-transform: uppercase;
  padding: 0.12rem 0.4rem;
  border-radius: 4px;
  color: #fff;
}

.sev-tag.critical, .sev-critical { background: #fee2e2; color: #991b1b; }
.sev-tag.high, .sev-high { background: #ffedd5; color: #9a3412; }
.sev-tag.medium, .sev-medium { background: #fef9c3; color: #854d0e; }
.sev-tag.low, .sev-low { background: #dbeafe; color: #1e40af; }

.sev-tag.critical { background: #dc2626; color: #fff; }
.sev-tag.high { background: #ea580c; color: #fff; }
.sev-tag.medium { background: #eab308; color: #78350f; }
.sev-tag.low { background: #3b82f6; color: #fff; }

.swimlane-empty {
  padding: 2.5rem;
  text-align: center;
  color: var(--text-muted);
  font-size: 0.85rem;
}

@media (max-width: 1100px) {
  .ig-segments,
  .ig-label-row,
  .ig-cards-row {
    grid-template-columns: repeat(var(--slot-count), minmax(76px, 1fr));
    gap: 0.55rem;
  }

  .event-card { max-width: 130px; min-height: 120px; }
  .th-entity { width: 210px; min-width: 210px; }
}

@media (max-width: 768px) {
  .tl-toolbar { flex-direction: column; align-items: flex-start; gap: 0.75rem; }
  .tl-toolbar-left { width: 100%; justify-content: space-between; }
  .view-mode-toggle { width: 100%; justify-content: space-between; }
  .vmt-btn { flex: 1; justify-content: center; padding: 0.35rem 0.4rem; font-size: 0.72rem; }
  .ig-stage { padding: 1.3rem 0.7rem 1rem; }
  .ig-label { font-size: 0.61rem; }
  .segment-date { font-size: 0.64rem; }
  .event-card { max-width: 112px; min-height: 108px; }
  .th-entity { width: 170px; min-width: 170px; }
  .th-slot { min-width: 115px; }
}
</style>
