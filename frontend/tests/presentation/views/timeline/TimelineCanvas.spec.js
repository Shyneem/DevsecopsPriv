import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import TimelineCanvas from '@/presentation/views/timeline/components/TimelineCanvas.vue'

const visibleSlots = [
  {
    startMs: 1000,
    endMs: 2000,
    painted: true,
    type: 'detection',
    tickLabel: '08/03',
    cardLabel: '08/03 2026',
    total: 2,
    pending: 2,
    resolved: 0,
    details: [
      { id: 1, agent_name: 'srv-web', cve_id: 'CVE-2023-1111', severity: 'CRITICAL', status: 'ACTIVE' },
      { id: 2, agent_name: 'srv-db', cve_id: 'CVE-2023-2222', severity: 'HIGH', status: 'ACTIVE' }
    ],
    byAgent: {
      'srv-web': {
        agent_name: 'srv-web',
        total: 1,
        pending: 1,
        resolved: 0,
        type: 'detection',
        cves: ['CVE-2023-1111'],
        severities: { critical: 1, high: 0, medium: 0, low: 0 },
        details: [{ id: 1, agent_name: 'srv-web', cve_id: 'CVE-2023-1111' }]
      },
      'srv-db': {
        agent_name: 'srv-db',
        total: 1,
        pending: 1,
        resolved: 0,
        type: 'detection',
        cves: ['CVE-2023-2222'],
        severities: { critical: 0, high: 1, medium: 0, low: 0 },
        details: [{ id: 2, agent_name: 'srv-db', cve_id: 'CVE-2023-2222' }]
      }
    },
    byCve: {
      'CVE-2023-1111': {
        cve_id: 'CVE-2023-1111',
        total: 1,
        pending: 1,
        resolved: 0,
        type: 'detection',
        severity: 'CRITICAL',
        agents: ['srv-web'],
        details: [{ id: 1 }]
      },
      'CVE-2023-2222': {
        cve_id: 'CVE-2023-2222',
        total: 1,
        pending: 1,
        resolved: 0,
        type: 'detection',
        severity: 'HIGH',
        agents: ['srv-db'],
        details: [{ id: 2 }]
      }
    }
  },
  {
    startMs: 2001,
    endMs: 3000,
    painted: false,
    type: 'none',
    tickLabel: '09/03',
    cardLabel: '09/03 2026',
    total: 0,
    pending: 0,
    resolved: 0,
    details: [],
    byAgent: {},
    byCve: {}
  }
]

const agentSummaryList = [
  {
    name: 'srv-web',
    totalVulns: 1,
    activeVulns: 1,
    resolvedVulns: 0,
    cves: ['CVE-2023-1111'],
    severities: { critical: 1, high: 0, medium: 0, low: 0 }
  },
  {
    name: 'srv-db',
    totalVulns: 1,
    activeVulns: 1,
    resolvedVulns: 0,
    cves: ['CVE-2023-2222'],
    severities: { critical: 0, high: 1, medium: 0, low: 0 }
  }
]

const cveSummaryList = [
  {
    cve_id: 'CVE-2023-1111',
    severity: 'CRITICAL',
    severityCategory: 'critical',
    severityWeight: 4,
    totalOccurrences: 1,
    activeOccurrences: 1,
    resolvedOccurrences: 0,
    affectedAgents: ['srv-web'],
    package_name: 'openssl'
  },
  {
    cve_id: 'CVE-2023-2222',
    severity: 'HIGH',
    severityCategory: 'high',
    severityWeight: 3,
    totalOccurrences: 1,
    activeOccurrences: 1,
    resolvedOccurrences: 0,
    affectedAgents: ['srv-db'],
    package_name: 'curl'
  }
]

describe('TimelineCanvas.vue', () => {
  it('emits navigation events and respects disabled states', async () => {
    const wrapper = mount(TimelineCanvas, {
      props: {
        allSlots: visibleSlots,
        visibleSlots,
        paintedCount: 1,
        yearLabel: '2026',
        activeZoom: { label: '30D', slotHours: 24 },
        canMoveLeft: true,
        canMoveRight: false,
        canZoomIn: true,
        canZoomOut: false
      }
    })

    const buttons = wrapper.findAll('.btn-icon')
    // buttons: 0: move-left, 1: zoom-out, 2: zoom-in, 3: move-right

    // Test move-left (enabled)
    await buttons[0].trigger('click')
    expect(wrapper.emitted('move-left')).toBeTruthy()

    // Test zoom-out (disabled)
    expect(buttons[1].element.disabled).toBe(true)
    await buttons[1].trigger('click')
    expect(wrapper.emitted('zoom-out')).toBeFalsy()

    // Test zoom-in (enabled)
    await buttons[2].trigger('click')
    expect(wrapper.emitted('zoom-in')).toBeTruthy()

    // Test move-right (disabled)
    expect(buttons[3].element.disabled).toBe(true)
    await buttons[3].trigger('click')
    expect(wrapper.emitted('move-right')).toBeFalsy()
  })

  it('computes stageStyle correctly', () => {
    const wrapper = mount(TimelineCanvas, {
      props: {
        allSlots: visibleSlots,
        visibleSlots,
        paintedCount: 1,
        activeZoom: { label: '30D', slotHours: 24 }
      }
    })

    const stage = wrapper.find('.ig-stage')
    expect(stage.attributes('style')).toContain('--slot-count: 2')
  })

  it('renders painted and empty slots correctly in global view', () => {
    const wrapper = mount(TimelineCanvas, {
      props: {
        allSlots: visibleSlots,
        visibleSlots,
        paintedCount: 1,
        activeZoom: { label: '30D', slotHours: 24 }
      }
    })

    const segments = wrapper.findAll('.ig-segment')
    expect(segments[0].classes()).toContain('detection')
    expect(segments[1].classes()).toContain('empty')
  })

  it('switches between view modes via toggle buttons', async () => {
    const wrapper = mount(TimelineCanvas, {
      props: {
        allSlots: visibleSlots,
        visibleSlots,
        paintedCount: 1,
        activeZoom: { label: '30D', slotHours: 24 },
        agentSummaryList,
        cveSummaryList,
        viewMode: 'global'
      }
    })

    const modeButtons = wrapper.findAll('.vmt-btn')
    expect(modeButtons.length).toBe(3)

    // Switch to agent view
    await modeButtons[1].trigger('click')
    expect(wrapper.emitted('update:viewMode')).toBeTruthy()
    expect(wrapper.emitted('update:viewMode')[0]).toEqual(['agent'])
    expect(wrapper.find('.swimlane-view').exists()).toBe(true)
    expect(wrapper.text()).toContain('srv-web')

    // Switch to CVE view
    await modeButtons[2].trigger('click')
    expect(wrapper.emitted('update:viewMode')[1]).toEqual(['cve'])
    expect(wrapper.text()).toContain('CVE-2023-1111')
  })

  it('renders agent swimlanes and handles agent slot click', async () => {
    const wrapper = mount(TimelineCanvas, {
      props: {
        allSlots: visibleSlots,
        visibleSlots,
        paintedCount: 1,
        activeZoom: { label: '30D', slotHours: 24 },
        agentSummaryList,
        cveSummaryList,
        viewMode: 'agent'
      }
    })

    expect(wrapper.findAll('.swimlane-row').length).toBe(2)
    const card = wrapper.find('.lane-event-card')
    expect(card.exists()).toBe(true)

    await card.trigger('click')
    expect(wrapper.emitted('open-slot')).toBeTruthy()
    expect(wrapper.emitted('open-slot')[0][1]).toEqual({ agent: 'srv-web' })
  })

  it('filters agents by search input', async () => {
    const wrapper = mount(TimelineCanvas, {
      props: {
        allSlots: visibleSlots,
        visibleSlots,
        paintedCount: 1,
        activeZoom: { label: '30D', slotHours: 24 },
        agentSummaryList,
        cveSummaryList,
        viewMode: 'agent'
      }
    })

    const searchInput = wrapper.find('.swimlane-input')
    await searchInput.setValue('srv-db')

    expect(wrapper.text()).toContain('srv-db')
    expect(wrapper.text()).not.toContain('srv-web')
  })

  it('renders CVE swimlanes and handles CVE slot click', async () => {
    const wrapper = mount(TimelineCanvas, {
      props: {
        allSlots: visibleSlots,
        visibleSlots,
        paintedCount: 1,
        activeZoom: { label: '30D', slotHours: 24 },
        agentSummaryList,
        cveSummaryList,
        viewMode: 'cve'
      }
    })

    expect(wrapper.findAll('.swimlane-row').length).toBe(2)
    const card = wrapper.find('.lane-event-card')
    expect(card.exists()).toBe(true)

    await card.trigger('click')
    expect(wrapper.emitted('open-slot')).toBeTruthy()
    expect(wrapper.emitted('open-slot')[0][1]).toEqual({ cve: 'CVE-2023-1111' })
  })

  it('filters CVEs by severity dropdown in cve view', async () => {
    const wrapper = mount(TimelineCanvas, {
      props: {
        allSlots: visibleSlots,
        visibleSlots,
        paintedCount: 1,
        activeZoom: { label: '30D', slotHours: 24 },
        agentSummaryList,
        cveSummaryList,
        viewMode: 'cve'
      }
    })

    const select = wrapper.find('.swimlane-select')
    await select.setValue('critical')

    expect(wrapper.text()).toContain('CVE-2023-1111')
    expect(wrapper.text()).not.toContain('CVE-2023-2222')
  })
})
